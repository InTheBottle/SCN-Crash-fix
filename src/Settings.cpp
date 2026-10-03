#include "Settings.h"

#include <cctype>
#include <fstream>

namespace
{
	bool g_logging = false;

	std::string Normalize(std::string_view a_text)
	{
		std::string out;
		for (const char ch : a_text) {
			if (!std::isspace(static_cast<unsigned char>(ch))) {
				out += static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
			}
		}
		return out;
	}
}

namespace Settings
{
	void Load()
	{
		std::ifstream file(R"(Data\SKSE\Plugins\ShadowSceneNodeCrashFix.ini)");
		if (!file) {
			return;
		}

		std::string line;
		while (std::getline(file, line)) {
			if (const auto comment = line.find_first_of(";#"); comment != std::string::npos) {
				line.erase(comment);
			}
			const auto equals = line.find('=');
			if (equals == std::string::npos) {
				continue;
			}
			const auto key = Normalize(std::string_view(line).substr(0, equals));
			const auto value = Normalize(std::string_view(line).substr(equals + 1));
			if (key == "enablelogging") {
				g_logging = value == "true" || value == "1" || value == "yes" || value == "on";
			}
		}
	}

	bool LoggingEnabled()
	{
		return g_logging;
	}
}
