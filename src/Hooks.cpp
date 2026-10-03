#include "Hooks.h"
#include "Registry.h"
#include "Settings.h"

#define WIN32_LEAN_AND_MEAN
#define PSAPI_VERSION 2
#include <Windows.h>

#include <Psapi.h>
#include <intrin.h>

namespace
{
	constexpr std::uint64_t kLogCap = 64;
	constexpr std::uint64_t kNormalLogCap = 16;
	constexpr int           kTryLockSpins = 256;

	struct Counter
	{
		std::atomic<std::uint64_t> count{ 0 };

		bool Log(std::uint64_t a_cap = kLogCap)
		{
			return Settings::LoggingEnabled() && count.fetch_add(1) < a_cap;
		}
	};

	Counter g_deadLightSkipped;
	Counter g_normalRelease;
	Counter g_staleRelease;
	Counter g_linkScrub;
	Counter g_roomScrubbed;
	Counter g_sharedNodeScrubbed;
	Counter g_portalScrubbed;
	Counter g_deferred;
	Counter g_drained;

	bool        g_drainInstalled = false;
	std::size_t g_exeSize = 0;

	std::array<std::uintptr_t, 5> g_lightVtables{};
	std::uintptr_t                g_roomVtable = 0;
	std::uintptr_t                g_sharedNodeVtable = 0;
	std::uintptr_t                g_portalVtable = 0;

	std::uintptr_t VtableOf(const void* a_object)
	{
		return *reinterpret_cast<const std::uintptr_t*>(a_object);
	}

	bool IsDeadLight(const void* a_light)
	{
		if (std::ranges::find(g_lightVtables, VtableOf(a_light)) == g_lightVtables.end()) {
			return true;
		}
		return *reinterpret_cast<const std::uint32_t*>(reinterpret_cast<std::uintptr_t>(a_light) + 0x8) == 0;
	}

	struct SlotHits
	{
		std::size_t queueAdd{ 0 };
		std::size_t queueRemove{ 0 };
		std::size_t dirty{ 0 };
		std::size_t active{ 0 };
		std::size_t activeShadow{ 0 };
		std::size_t accum{ 0 };

		std::size_t Total() const
		{
			return queueAdd + queueRemove + dirty + active + activeShadow + accum;
		}

		std::size_t ArraysTouched() const
		{
			return (queueAdd ? 1 : 0) + (queueRemove ? 1 : 0) + (dirty ? 1 : 0) + (active ? 1 : 0) + (activeShadow ? 1 : 0) + (accum ? 1 : 0);
		}

		SlotHits& operator+=(const SlotHits& a_rhs)
		{
			queueAdd += a_rhs.queueAdd;
			queueRemove += a_rhs.queueRemove;
			dirty += a_rhs.dirty;
			active += a_rhs.active;
			activeShadow += a_rhs.activeShadow;
			accum += a_rhs.accum;
			return *this;
		}

		std::string Describe() const
		{
			std::string out;
			const auto  add = [&](const char* a_name, std::size_t a_count) {
				 if (a_count) {
					 if (!out.empty()) {
						 out += ' ';
					 }
					 out += std::format("{}:{}", a_name, a_count);
				 }
			};
			add("lightQueueAdd", queueAdd);
			add("lightQueueRemove", queueRemove);
			add("dirtyQueue", dirty);
			add("activeLights", active);
			add("activeShadowLights", activeShadow);
			add("shadowLightsAccum", accum);
			return out;
		}
	};

	struct ModuleInfo
	{
		std::uintptr_t begin;
		std::uintptr_t end;
		std::string    name;
	};

	std::mutex              g_moduleLock;
	std::vector<ModuleInfo> g_modules;

	std::size_t ExeImageSize()
	{
		const auto  base = REL::Module::get().base();
		const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
		const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
		return nt->OptionalHeader.SizeOfImage;
	}

	void BuildModuleMap()
	{
		std::vector<ModuleInfo> modules;
		std::vector<HMODULE>    handles(4096);
		DWORD                   needed = 0;
		const auto              process = ::GetCurrentProcess();
		if (::EnumProcessModules(process, handles.data(), static_cast<DWORD>(handles.size() * sizeof(HMODULE)), &needed)) {
			const auto count = std::min<std::size_t>(needed / sizeof(HMODULE), handles.size());
			modules.reserve(count);
			for (std::size_t i = 0; i < count; ++i) {
				MODULEINFO info{};
				char       name[MAX_PATH]{};
				if (::GetModuleInformation(process, handles[i], &info, sizeof(info)) && ::GetModuleBaseNameA(process, handles[i], name, MAX_PATH)) {
					const auto begin = reinterpret_cast<std::uintptr_t>(info.lpBaseOfDll);
					modules.push_back({ begin, begin + info.SizeOfImage, name });
				}
			}
		}
		std::scoped_lock lock(g_moduleLock);
		g_modules = std::move(modules);
	}

	std::string DescribeAddress(const void* a_address)
	{
		const auto address = reinterpret_cast<std::uintptr_t>(a_address);
		{
			std::scoped_lock lock(g_moduleLock);
			for (const auto& entry : g_modules) {
				if (address >= entry.begin && address < entry.end) {
					return std::format("{}+{:X}", entry.name, address - entry.begin);
				}
			}
		}
		const auto base = REL::Module::get().base();
		if (address >= base && address < base + g_exeSize) {
			return std::format("exe+{:X}", address - base);
		}
		return std::format("{:#x}", address);
	}

	struct Backtrace
	{
		std::array<void*, 16> frames{};
		std::uint16_t         count{ 0 };
	};

	Backtrace CaptureBacktrace()
	{
		Backtrace bt;
		bt.count = ::RtlCaptureStackBackTrace(1, static_cast<ULONG>(bt.frames.size()), bt.frames.data(), nullptr);
		return bt;
	}

	struct ReleaseSite
	{
		std::uintptr_t begin;
		std::uintptr_t end;
		const char*    name;
	};

	std::vector<ReleaseSite> g_releaseSites;

	void ResolveReleaseSites()
	{
		if (REL::Module::IsVR()) {
			return;
		}
		struct Entry
		{
			REL::RelocationID id;
			std::size_t       seSize;
			std::size_t       aeSize;
			const char*       name;
		};
		const Entry entries[] = {
			{ REL::RelocationID(99701, 106335), 0x630, 0x7D7, "ShadowSceneNode::ProcessLightQueues" },
			{ REL::RelocationID(99699, 106333), 0x110, 0x14D, "ShadowSceneNode::RemoveLightImpl" },
			{ REL::RelocationID(99702, 106336), 0x3C0, 0x446, "ShadowSceneNode::FlushLightRemovals" },
			{ REL::RelocationID(99704, 106338), 0x2B0, 0x157, "ShadowSceneNode::ClearLightArrays" },
			{ REL::RelocationID(99741, 106385), 0x5A0, 0x547, "ShadowSceneNode::SetPortalGraph" },
		};
		for (const auto& entry : entries) {
			const auto begin = entry.id.address();
			const auto size = REL::Module::IsAE() ? entry.aeSize : entry.seSize;
			g_releaseSites.push_back({ begin, begin + size, entry.name });
		}
	}

	const char* FindReleaseSite(const Backtrace& a_bt)
	{
		for (std::uint16_t i = 0; i < a_bt.count; ++i) {
			const auto address = reinterpret_cast<std::uintptr_t>(a_bt.frames[i]);
			for (const auto& site : g_releaseSites) {
				if (address >= site.begin && address < site.end) {
					return site.name;
				}
			}
		}
		return nullptr;
	}

	void LogBacktrace(const Backtrace& a_bt)
	{
		for (std::uint16_t i = 0; i < a_bt.count; ++i) {
			logger::warn("    [{:2}] {}"sv, i, DescribeAddress(a_bt.frames[i]));
		}
	}

	bool TryLock(RE::BSSpinLock& a_lock)
	{
		auto*      raw = reinterpret_cast<volatile long*>(std::addressof(a_lock));
		const auto thread = static_cast<long>(::GetCurrentThreadId());
		if (raw[0] == thread) {
			::_InterlockedIncrement(&raw[1]);
			return true;
		}
		for (int i = 0; i < kTryLockSpins; ++i) {
			if (::_InterlockedCompareExchange(&raw[1], 1, 0) == 0) {
				raw[0] = thread;
				return true;
			}
			_mm_pause();
		}
		return false;
	}

	class ScopedTryLock
	{
	public:
		explicit ScopedTryLock(RE::BSSpinLock& a_lock) :
			_lock(a_lock),
			_held(TryLock(a_lock))
		{}

		~ScopedTryLock()
		{
			if (_held) {
				_lock.Unlock();
			}
		}

		ScopedTryLock(const ScopedTryLock&) = delete;
		ScopedTryLock& operator=(const ScopedTryLock&) = delete;

		explicit operator bool() const
		{
			return _held;
		}

	private:
		RE::BSSpinLock& _lock;
		bool            _held;
	};

	template <class T, class Pred>
	std::size_t NullSlotsIf(RE::BSTArray<RE::NiPointer<T>>& a_array, Pred&& a_pred)
	{
		std::size_t hits = 0;
		auto*       raw = reinterpret_cast<void**>(a_array.data());
		for (std::uint32_t i = 0; i < a_array.size(); ++i) {
			if (raw[i] && a_pred(static_cast<const void*>(raw[i]))) {
				raw[i] = nullptr;
				++hits;
			}
		}
		return hits;
	}

	template <class T, class Pred>
	std::size_t NullSlotsIf(RE::BSTArray<T*>& a_array, Pred&& a_pred)
	{
		std::size_t hits = 0;
		for (std::uint32_t i = 0; i < a_array.size(); ++i) {
			if (a_array[i] && a_pred(static_cast<const void*>(a_array[i]))) {
				a_array[i] = nullptr;
				++hits;
			}
		}
		return hits;
	}

	template <class T, class Pred>
	std::size_t EraseIf(RE::BSTArray<T*>& a_array, Pred&& a_pred)
	{
		std::size_t hits = 0;
		for (auto it = a_array.begin(); it != a_array.end();) {
			if (*it && a_pred(static_cast<const void*>(*it))) {
				it = a_array.erase(it);
				++hits;
			} else {
				++it;
			}
		}
		return hits;
	}

	struct PortalItem
	{
		PortalItem*   next;
		PortalItem*   prev;
		RE::BSPortal* element;
	};

	RE::BSTArray<RE::BSLight*>& RoomLights(RE::BSMultiBoundRoom* a_room)
	{
		return REL::RelocateMember<RE::BSTArray<RE::BSLight*>>(a_room, 0x180, 0x1A8);
	}

	PortalItem* RoomPortalHead(RE::BSMultiBoundRoom* a_room)
	{
		return REL::RelocateMember<PortalItem*>(a_room, 0x138, 0x160);
	}

	RE::BSTArray<RE::BSLight*>& SharedNodeLights(RE::BSPortalSharedNode* a_node)
	{
		return REL::RelocateMember<RE::BSTArray<RE::BSLight*>>(a_node, 0x128, 0x150);
	}

	RE::BSPortal* SharedNodePortal(RE::BSPortalSharedNode* a_node)
	{
		return REL::RelocateMember<RE::BSPortal*>(a_node, 0x140, 0x168);
	}

	RE::ShadowSceneNode* SceneNode(std::size_t a_index)
	{
		return RE::BSShaderManager::State::GetSingleton().shadowSceneNode[a_index];
	}

	std::optional<std::size_t> IndexOfNode(const RE::ShadowSceneNode* a_node)
	{
		for (std::size_t i = 0; i < 4; ++i) {
			if (SceneNode(i) == a_node) {
				return i;
			}
		}
		return std::nullopt;
	}

	template <class Pred>
	SlotHits ScrubNodeLocked(RE::ShadowSceneNode* a_node, Pred&& a_pred)
	{
		auto&    data = a_node->GetRuntimeData();
		SlotHits hits;
		hits.queueAdd = NullSlotsIf(data.lightQueueAdd, a_pred);
		hits.queueRemove = NullSlotsIf(data.lightQueueRemove, a_pred);
		hits.dirty = NullSlotsIf(data.unk190, a_pred);
		hits.active = NullSlotsIf(data.activeLights, a_pred);
		hits.activeShadow = NullSlotsIf(data.activeShadowLights, a_pred);
		hits.accum = NullSlotsIf(data.shadowLightsAccum, a_pred);
		return hits;
	}

	template <class Pred>
	std::size_t EraseLightLinksLocked(RE::ShadowSceneNode* a_world, Pred&& a_pred)
	{
		auto* graph = a_world->GetRuntimeData().portalGraph;
		if (!graph) {
			return 0;
		}
		std::size_t hits = 0;
		for (auto& roomPtr : graph->rooms) {
			auto* room = roomPtr.get();
			if (!room) {
				continue;
			}
			hits += EraseIf(RoomLights(room), a_pred);
			for (auto* item = RoomPortalHead(room); item; item = item->next) {
				auto* portal = item->element;
				if (!portal) {
					continue;
				}
				if (auto* node = portal->portalSharedNode.get()) {
					hits += EraseIf(SharedNodeLights(node), a_pred);
				}
			}
		}
		return hits;
	}

	struct PendingWork
	{
		using Set = std::unordered_set<const void*>;

		std::mutex                 lock;
		std::array<Set, 4>         lights;
		Set                        lightLinks;
		Set                        rooms;
		Set                        portals;
		Set                        sharedNodes;
		std::atomic<std::uint32_t> count{ 0 };

		void Recount()
		{
			std::size_t total = lightLinks.size() + rooms.size() + portals.size() + sharedNodes.size();
			for (const auto& set : lights) {
				total += set.size();
			}
			count.store(static_cast<std::uint32_t>(total), std::memory_order_release);
		}

		void DeferLight(std::size_t a_index, const void* a_light)
		{
			std::scoped_lock guard(lock);
			lights[a_index].insert(a_light);
			if (a_index == 0) {
				lightLinks.insert(a_light);
			}
			Recount();
		}

		void DeferRoom(const void* a_room)
		{
			std::scoped_lock guard(lock);
			rooms.insert(a_room);
			Recount();
		}

		void DeferPortal(const void* a_portal)
		{
			std::scoped_lock guard(lock);
			portals.insert(a_portal);
			Recount();
		}

		void DeferSharedNode(const void* a_node, const void* a_portal)
		{
			std::scoped_lock guard(lock);
			sharedNodes.insert(a_node);
			if (a_portal) {
				portals.insert(a_portal);
			}
			Recount();
		}

		void ForgetLight(const void* a_light)
		{
			if (count.load(std::memory_order_acquire) == 0) {
				return;
			}
			std::scoped_lock guard(lock);
			for (auto& set : lights) {
				set.erase(a_light);
			}
			lightLinks.erase(a_light);
			Recount();
		}

	};

	PendingWork g_pending;

	void OnLightDestroyed(RE::BSLight* a_light, std::string_view a_class)
	{
		Registry::RemoveLight(a_light);

		const auto address = reinterpret_cast<std::uintptr_t>(a_light);
		const auto isLight = [a_light](const void* a_ptr) {
			return a_ptr == a_light;
		};

		SlotHits    hits;
		std::size_t linkHits = 0;
		std::size_t deferred = 0;
		for (std::size_t i = 0; i < 4; ++i) {
			auto* node = SceneNode(i);
			if (!node) {
				continue;
			}
			if (ScopedTryLock lock(node->GetRuntimeData().lightQueueLock); lock) {
				hits += ScrubNodeLocked(node, isLight);
				if (i == 0) {
					linkHits = EraseLightLinksLocked(node, isLight);
				}
			} else if (g_drainInstalled) {
				g_pending.DeferLight(i, a_light);
				++deferred;
			}
		}

		if (deferred && g_deferred.Log()) {
			logger::info("{} {:#x} freed on thread {} while {} scene node(s) were busy; cleanup queued for the next light pass"sv, a_class, address, ::GetCurrentThreadId(), deferred);
		}

		if (hits.Total() && Settings::LoggingEnabled()) {
			const auto  bt = CaptureBacktrace();
			const auto* site = FindReleaseSite(bt);
			if (site && hits.ArraysTouched() == 1) {
				if (g_normalRelease.Log(kNormalLogCap)) {
					logger::info("{} {:#x} freed by {} while its own slot was still populated ({}); slot cleared, this is the engine's normal release order"sv, a_class, address, site, hits.Describe());
				}
			} else if (g_staleRelease.Log()) {
				logger::warn("{} {:#x} freed while still referenced by a ShadowSceneNode ({}){}; slots cleared"sv, a_class, address, hits.Describe(), site ? std::format(", release site {}", site) : std::string{});
				LogBacktrace(bt);
			}
		}

		if (linkHits && g_linkScrub.Log()) {
			logger::info("{} {:#x} freed while linked from {} room or portal light list(s); links removed"sv, a_class, address, linkHits);
		}
	}

	void OnRoomDestroyed(RE::BSMultiBoundRoom* a_room)
	{
		const auto scan = [a_room]() {
			const auto isRoom = [a_room](const void* a_ptr) {
				return a_ptr == a_room;
			};
			Registry::LightScope scope;
			std::size_t          hits = 0;
			for (auto* light : RoomLights(a_room)) {
				if (scope.Contains(light)) {
					hits += EraseIf(light->rooms, isRoom);
				}
			}
			return hits;
		};

		std::size_t hits = 0;
		if (auto* world = SceneNode(0)) {
			if (ScopedTryLock lock(world->GetRuntimeData().lightQueueLock); lock) {
				hits = scan();
			} else {
				if (g_drainInstalled) {
					g_pending.DeferRoom(a_room);
				}
				return;
			}
		} else {
			hits = scan();
		}
		if (hits && g_roomScrubbed.Log()) {
			logger::info("BSMultiBoundRoom {:#x} destroyed while {} live light link(s) still pointed at it; links removed"sv, reinterpret_cast<std::uintptr_t>(a_room), hits);
		}
	}

	void OnSharedNodeDestroyed(RE::BSPortalSharedNode* a_node)
	{
		auto*      portal = SharedNodePortal(a_node);
		const auto scan = [a_node, portal]() {
			const auto isNode = [a_node](const void* a_ptr) {
				return a_ptr == a_node;
			};
			const auto isPortal = [portal](const void* a_ptr) {
				return a_ptr == portal;
			};
			Registry::LightScope scope;
			std::size_t          hits = 0;
			for (auto* light : SharedNodeLights(a_node)) {
				if (!scope.Contains(light)) {
					continue;
				}
				hits += EraseIf(light->portalSharedNodes, isNode);
				if (portal) {
					hits += EraseIf(light->portals, isPortal);
				}
			}
			return hits;
		};

		std::size_t hits = 0;
		if (auto* world = SceneNode(0)) {
			if (ScopedTryLock lock(world->GetRuntimeData().lightQueueLock); lock) {
				hits = scan();
			} else {
				if (g_drainInstalled) {
					g_pending.DeferSharedNode(a_node, portal);
				}
				return;
			}
		} else {
			hits = scan();
		}
		if (hits && g_sharedNodeScrubbed.Log()) {
			logger::info("BSPortalSharedNode {:#x} destroyed while {} live light link(s) still pointed at it; links removed"sv, reinterpret_cast<std::uintptr_t>(a_node), hits);
		}
	}

	void OnPortalDestroyed(RE::BSPortal* a_portal)
	{
		auto* node = a_portal->portalSharedNode.get();
		if (!node) {
			return;
		}
		const auto scan = [a_portal, node]() {
			const auto isPortal = [a_portal](const void* a_ptr) {
				return a_ptr == a_portal;
			};
			Registry::LightScope scope;
			std::size_t          hits = 0;
			for (auto* light : SharedNodeLights(node)) {
				if (scope.Contains(light)) {
					hits += EraseIf(light->portals, isPortal);
				}
			}
			return hits;
		};

		std::size_t hits = 0;
		if (auto* world = SceneNode(0)) {
			if (ScopedTryLock lock(world->GetRuntimeData().lightQueueLock); lock) {
				hits = scan();
			} else {
				if (g_drainInstalled) {
					g_pending.DeferPortal(a_portal);
				}
				return;
			}
		} else {
			hits = scan();
		}
		if (hits && g_portalScrubbed.Log()) {
			logger::info("BSPortal {:#x} destroyed while {} live light link(s) still pointed at it; links removed"sv, reinterpret_cast<std::uintptr_t>(a_portal), hits);
		}
	}

	void Drain(RE::ShadowSceneNode* a_node)
	{
		const auto index = IndexOfNode(a_node);
		if (!index) {
			return;
		}

		PendingWork::Set lights;
		PendingWork::Set links;
		PendingWork::Set rooms;
		PendingWork::Set portals;
		PendingWork::Set nodes;
		{
			std::scoped_lock guard(g_pending.lock);
			lights.swap(g_pending.lights[*index]);
			if (*index == 0) {
				links.swap(g_pending.lightLinks);
				rooms.swap(g_pending.rooms);
				portals.swap(g_pending.portals);
				nodes.swap(g_pending.sharedNodes);
			}
			g_pending.Recount();
		}
		if (lights.empty() && links.empty() && rooms.empty() && portals.empty() && nodes.empty()) {
			return;
		}

		std::erase_if(rooms, [](const void* a_ptr) {
			return VtableOf(a_ptr) == g_roomVtable;
		});
		std::erase_if(portals, [](const void* a_ptr) {
			return VtableOf(a_ptr) == g_portalVtable;
		});
		std::erase_if(nodes, [](const void* a_ptr) {
			return VtableOf(a_ptr) == g_sharedNodeVtable;
		});

		const auto in = [](const PendingWork::Set& a_set) {
			return [&a_set](const void* a_ptr) {
				return a_set.contains(a_ptr);
			};
		};
		const auto deadIn = [](const PendingWork::Set& a_set) {
			return [&a_set](const void* a_ptr) {
				return a_set.contains(a_ptr) && IsDeadLight(a_ptr);
			};
		};

		SlotHits    slotHits;
		std::size_t linkHits = 0;
		{
			RE::BSSpinLockGuard lock(a_node->GetRuntimeData().lightQueueLock);
			if (!lights.empty()) {
				slotHits = ScrubNodeLocked(a_node, deadIn(lights));
			}
			if (!links.empty()) {
				linkHits += EraseLightLinksLocked(a_node, deadIn(links));
			}
			if (!rooms.empty() || !portals.empty() || !nodes.empty()) {
				Registry::LightScope scope;
				for (auto* light : scope.All()) {
					if (!rooms.empty()) {
						linkHits += EraseIf(light->rooms, in(rooms));
					}
					if (!portals.empty()) {
						linkHits += EraseIf(light->portals, in(portals));
					}
					if (!nodes.empty()) {
						linkHits += EraseIf(light->portalSharedNodes, in(nodes));
					}
				}
			}
		}

		if ((slotHits.Total() || linkHits) && g_drained.Log()) {
			logger::warn("Deferred cleanup on scene node {}: cleared {} stale slot(s) ({}) and {} stale link(s)"sv, *index, slotHits.Total(), slotHits.Describe(), linkHits);
		}
	}

	template <std::size_t I>
	struct LightVtbl
	{
		using DtorFn = void (*)(RE::BSLight*, std::uint32_t);
		using SetLightFn = bool (*)(RE::BSLight*, RE::NiLight*);

		static inline REL::Relocation<DtorFn>     dtor;
		static inline REL::Relocation<SetLightFn> setLight;
		static inline std::string_view            name;

		static void Dtor(RE::BSLight* a_this, std::uint32_t a_flags)
		{
			OnLightDestroyed(a_this, name);
			dtor(a_this, a_flags);
		}

		static bool SetLight(RE::BSLight* a_this, RE::NiLight* a_light)
		{
			g_pending.ForgetLight(a_this);
			Registry::AddLight(a_this);
			return setLight(a_this, a_light);
		}
	};

	struct RoomVtbl
	{
		using DtorFn = void (*)(RE::BSMultiBoundRoom*, std::uint32_t);

		static inline REL::Relocation<DtorFn> dtor;

		static void Dtor(RE::BSMultiBoundRoom* a_this, std::uint32_t a_flags)
		{
			OnRoomDestroyed(a_this);
			dtor(a_this, a_flags);
		}
	};

	struct SharedNodeVtbl
	{
		using DtorFn = void (*)(RE::BSPortalSharedNode*, std::uint32_t);

		static inline REL::Relocation<DtorFn> dtor;

		static void Dtor(RE::BSPortalSharedNode* a_this, std::uint32_t a_flags)
		{
			OnSharedNodeDestroyed(a_this);
			dtor(a_this, a_flags);
		}
	};

	struct PortalVtbl
	{
		using DtorFn = void (*)(RE::BSPortal*, std::uint32_t);

		static inline REL::Relocation<DtorFn> dtor;

		static void Dtor(RE::BSPortal* a_this, std::uint32_t a_flags)
		{
			OnPortalDestroyed(a_this);
			dtor(a_this, a_flags);
		}
	};

	struct EvaluateGuard
	{
		using Fn = void (*)(RE::ShadowSceneNode*, RE::BSLight*);

		static inline REL::Relocation<Fn> original;

		static void Thunk(RE::ShadowSceneNode* a_node, RE::BSLight* a_light)
		{
			if (!a_light) {
				return;
			}

			if (IsDeadLight(a_light)) {
				SlotHits hits;
				if (ScopedTryLock lock(a_node->GetRuntimeData().lightQueueLock); lock) {
					hits = ScrubNodeLocked(a_node, [a_light](const void* a_ptr) {
						return a_ptr == a_light;
					});
				}
				if (g_deadLightSkipped.Log()) {
					logger::warn("Skipped portal evaluation of dead BSLight {:#x}; cleared {} slot(s) ({})"sv, reinterpret_cast<std::uintptr_t>(a_light), hits.Total(), hits.Describe());
				}
				return;
			}

			if (!a_light->light) {
				if (g_deadLightSkipped.Log()) {
					logger::warn("Skipped portal evaluation of BSLight {:#x} that has no NiLight"sv, reinterpret_cast<std::uintptr_t>(a_light));
				}
				return;
			}

			Registry::AddLight(a_light);
			original(a_node, a_light);
		}
	};

	struct ProcessQueuesHook
	{
		using Fn = std::uintptr_t (*)(RE::ShadowSceneNode*, std::uintptr_t);

		static inline REL::Relocation<Fn> original;

		static std::uintptr_t Thunk(RE::ShadowSceneNode* a_node, std::uintptr_t a_arg)
		{
			if (a_node && g_pending.count.load(std::memory_order_acquire)) {
				Drain(a_node);
			}
			return original(a_node, a_arg);
		}
	};

	template <class Hook>
	std::size_t PatchCalls(REL::RelocationID a_caller, std::size_t a_scanSize, std::uintptr_t a_target)
	{
		auto&       trampoline = SKSE::GetTrampoline();
		const auto  base = a_caller.address();
		std::size_t patched = 0;
		for (std::size_t i = 0; i + 5 <= a_scanSize; ++i) {
			const auto site = base + i;
			if (*reinterpret_cast<const std::uint8_t*>(site) != 0xE8) {
				continue;
			}
			const auto rel = *reinterpret_cast<const std::int32_t*>(site + 1);
			if (site + 5 + rel != a_target) {
				continue;
			}
			Hook::original = trampoline.write_call<5>(site, &Hook::Thunk);
			++patched;
			i += 4;
		}
		return patched;
	}

	std::size_t SizeFor(std::size_t a_se, std::size_t a_ae)
	{
		return REL::Module::IsAE() ? a_ae : a_se;
	}

	template <std::size_t I>
	void InstallLightVtable(const REL::VariantID& a_id, std::string_view a_name)
	{
		REL::Relocation<std::uintptr_t> vtbl{ a_id };
		g_lightVtables[I] = vtbl.address();
		LightVtbl<I>::name = a_name;
		LightVtbl<I>::dtor = vtbl.write_vfunc(0, &LightVtbl<I>::Dtor);
		LightVtbl<I>::setLight = vtbl.write_vfunc(2, &LightVtbl<I>::SetLight);
		logger::info("Hooked {} destructor and SetLight (vtable {:#x})"sv, a_name, vtbl.address());
	}
}

namespace Hooks
{
	bool Install()
	{
		g_exeSize = ExeImageSize();
		ResolveReleaseSites();

		InstallLightVtable<0>(RE::VTABLE_BSLight[0], "BSLight"sv);
		InstallLightVtable<1>(RE::VTABLE_BSShadowLight[0], "BSShadowLight"sv);
		InstallLightVtable<2>(RE::VTABLE_BSShadowDirectionalLight[0], "BSShadowDirectionalLight"sv);
		InstallLightVtable<3>(RE::VTABLE_BSShadowFrustumLight[0], "BSShadowFrustumLight"sv);
		InstallLightVtable<4>(RE::VTABLE_BSShadowParabolicLight[0], "BSShadowParabolicLight"sv);

		{
			REL::Relocation<std::uintptr_t> vtbl{ RE::VTABLE_BSMultiBoundRoom[0] };
			g_roomVtable = vtbl.address();
			RoomVtbl::dtor = vtbl.write_vfunc(0x0, &RoomVtbl::Dtor);
			logger::info("Hooked BSMultiBoundRoom destructor (vtable {:#x})"sv, vtbl.address());
		}
		{
			REL::Relocation<std::uintptr_t> vtbl{ RE::VTABLE_BSPortalSharedNode[0] };
			g_sharedNodeVtable = vtbl.address();
			SharedNodeVtbl::dtor = vtbl.write_vfunc(0x0, &SharedNodeVtbl::Dtor);
			logger::info("Hooked BSPortalSharedNode destructor (vtable {:#x})"sv, vtbl.address());
		}
		{
			REL::Relocation<std::uintptr_t> vtbl{ RE::VTABLE_BSPortal[0] };
			g_portalVtable = vtbl.address();
			PortalVtbl::dtor = vtbl.write_vfunc(0x0, &PortalVtbl::Dtor);
			logger::info("Hooked BSPortal destructor (vtable {:#x})"sv, vtbl.address());
		}

		if (REL::Module::IsVR()) {
			logger::info("Skyrim VR: call-site hooks not installed (no verified call-site data); destructor hooks are active and never wait on engine locks"sv);
			return true;
		}

		const REL::RelocationID processQueues(99701, 106335);
		const REL::RelocationID evaluate(99708, 106342);
		const REL::RelocationID frameWrapper(99703, 106337);
		const REL::RelocationID setPortalGraph(99741, 106385);

		const auto guardSites = PatchCalls<EvaluateGuard>(processQueues, SizeFor(0x630, 0x7D7), evaluate.address());
		if (guardSites == 0) {
			logger::warn("Could not locate any call site of the light evaluation function inside the light queue processor; guard not installed"sv);
		} else {
			logger::info("Light evaluation guard installed at {} call site(s)"sv, guardSites);
		}

		const auto drainSites =
			PatchCalls<ProcessQueuesHook>(frameWrapper, SizeFor(0x50, 0x4A), processQueues.address()) +
			PatchCalls<ProcessQueuesHook>(setPortalGraph, SizeFor(0x5A0, 0x547), processQueues.address());
		g_drainInstalled = drainSites > 0;
		if (g_drainInstalled) {
			logger::info("Deferred cleanup hook installed at {} call site(s)"sv, drainSites);
		} else {
			logger::warn("Could not locate the light queue processor call sites; cleanup that cannot run immediately will be skipped"sv);
		}
		return true;
	}

	void OnDataLoaded()
	{
		BuildModuleMap();
		std::scoped_lock lock(g_moduleLock);
		logger::info("Module map built with {} module(s)"sv, g_modules.size());
	}
}
