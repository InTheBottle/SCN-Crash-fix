#include "Registry.h"

namespace
{
	std::mutex                       g_lightLock;
	std::unordered_set<RE::BSLight*> g_lights;
}

namespace Registry
{
	void AddLight(RE::BSLight* a_light)
	{
		if (!a_light) {
			return;
		}
		std::scoped_lock lock(g_lightLock);
		g_lights.insert(a_light);
	}

	bool RemoveLight(RE::BSLight* a_light)
	{
		std::scoped_lock lock(g_lightLock);
		return g_lights.erase(a_light) != 0;
	}

	std::size_t LightCount()
	{
		std::scoped_lock lock(g_lightLock);
		return g_lights.size();
	}

	LightScope::LightScope() :
		_lock(g_lightLock)
	{}

	bool LightScope::Contains(const RE::BSLight* a_light) const
	{
		return a_light && g_lights.contains(const_cast<RE::BSLight*>(a_light));
	}

	const std::unordered_set<RE::BSLight*>& LightScope::All() const
	{
		return g_lights;
	}
}
