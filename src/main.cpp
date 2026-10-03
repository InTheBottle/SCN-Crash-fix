#include "Hooks.h"
#include "Settings.h"

namespace
{
	void OnMessage(SKSE::MessagingInterface::Message* a_message)
	{
		if (a_message && a_message->type == SKSE::MessagingInterface::kDataLoaded) {
			Hooks::OnDataLoaded();
		}
	}
}

SKSEPluginInfo(
	.Version = Plugin::VERSION,
	.Name = Plugin::NAME,
	.Author = "InTheBottle"sv,
	.RuntimeCompatibility = SKSE::VersionIndependence::AddressLibrary
)

SKSE_PLUGIN_LOAD(const SKSE::LoadInterface* a_skse)
{
	Settings::Load();

	SKSE::Init(a_skse, { .log = Settings::LoggingEnabled(), .trampoline = true, .trampolineSize = 256 });

	logger::info("{} v{}"sv, Plugin::NAME, Plugin::VERSION.string());
	logger::info("Runtime {} ({})"sv, REL::Module::get().version().string(), REL::Module::IsVR() ? "VR"sv : REL::Module::IsAE() ? "AE"sv : "SE"sv);

	if (!Hooks::Install()) {
		logger::error("Hook installation failed; the plugin is inactive"sv);
		return true;
	}

	if (Settings::LoggingEnabled()) {
		if (const auto* messaging = SKSE::GetMessagingInterface()) {
			messaging->RegisterListener(OnMessage);
		}
	}

	logger::info("Ready"sv);
	return true;
}
