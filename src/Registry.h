#pragma once

namespace Registry
{
	void        AddLight(RE::BSLight* a_light);
	bool        RemoveLight(RE::BSLight* a_light);
	std::size_t LightCount();

	class LightScope
	{
	public:
		LightScope();

		[[nodiscard]] bool                                    Contains(const RE::BSLight* a_light) const;
		[[nodiscard]] const std::unordered_set<RE::BSLight*>& All() const;

	private:
		std::unique_lock<std::mutex> _lock;
	};
}
