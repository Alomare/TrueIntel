-- True Intel: English texts, the source of every translation.
-- Translators: see TRANSLATING.md in Mod Options Menu's repository (the same files and tool work for this mod).
-- Every text is one line of an armor passive's description in the Armory, in place of the game's own line: write it
-- like the game's passive descriptions in your language. Keep <c=#COLOR> and </c> around the number: they colour it
-- like the game's own numbers. #BONUS is the game's own number with its unit (30% or 30), filled in by the game in
-- your language's format; {number} is filled in by the mod (write the % sign as your language writes it). A line
-- should be about as long as the game's line it replaces.
return {
    mod = 'true_intel',
    title = 'True Intel',
    language = 'en',
    strings = {
        -- The game's own reload, ammo and sidearm lines, shown with the real number (the one the passive applies)
        -- wherever the game's line states another. {number} is a whole percent.
        ['line.reload_primary'] = 'Increases reload speed of primary weapons by <c=#COLOR>{number}%</c>.',
        ['line.reload_support'] = 'Increases reload speed of support weapons by <c=#COLOR>{number}%</c>.',
        ['line.reload_sidearm'] = 'Increases sidearms reload speed by <c=#COLOR>{number}%</c>.',
        ['line.draw_sidearm'] = 'Sidearm draw/holster speed increased by <c=#COLOR>{number}%</c>.',
        ['line.recoil_sidearm'] = 'Sidearm recoil reduced by <c=#COLOR>{number}%</c>.',
        ['line.ammo'] = 'Increases ammo capacity of all weapons by <c=#COLOR>{number}%</c>. Does not affect weapon backpacks.',
        -- Replaces "Provides a higher armor rating". {number} is how much of the Armory's ARMOR RATING the passive
        -- provides (50, 30 or 25): use the game's name for that stat.
        ['line.armor'] = 'Provides <c=#COLOR>+{number}</c> armor rating.',
        -- Replaces "Increases weapon ergonomics to reduce drag on weapon movement". #BONUS is 30 or 20 ergonomics
        -- points (the weapon stat the game shows as ERGONOMICS); a weapon's ergonomics never goes over 100.
        ['line.ergonomics'] = 'Increases weapon ergonomics by <c=#COLOR>#BONUS</c> (max 100) to reduce weapon drag.',
        -- Replaces "When the wearer takes damage, they regain some stamina". #BONUS is 2: the wearer regains 2% of the
        -- stamina bar for every 1% of their health lost. Colour both numbers.
        ['line.stamina'] = 'When the wearer takes damage, they regain <c=#COLOR>#BONUS%</c> stamina per <c=#COLOR>1%</c> of health lost.',
        -- Replaces "Bearer is more resistant to being knocked prone". #BONUS is 30%: hits that knock a Helldiver
        -- prone count 30% less force against the bearer.
        ['line.knockdown'] = 'Reduces knockdown force against the bearer by <c=#COLOR>#BONUS</c>.',
        -- Replaces "Increases the wearer's walking and running speed". #BONUS is 10%: the default movement speed
        -- (jogging) and the sprint speed are both 10% faster; walking (the slow toggle) is not.
        ['line.speed'] = 'Increases the wearer\'s jogging and sprinting speed by <c=#COLOR>#BONUS</c>.',
    },
    -- Characters, markup included (the Armory's passive panel fits about three lines of about 75 visible characters).
    limits = {['line.reload_primary'] = 160, ['line.reload_support'] = 160, ['line.reload_sidearm'] = 160,
              ['line.draw_sidearm'] = 160, ['line.recoil_sidearm'] = 160, ['line.ammo'] = 200, ['line.armor'] = 160,
              ['line.ergonomics'] = 160, ['line.stamina'] = 160, ['line.knockdown'] = 160, ['line.speed'] = 160},
}
