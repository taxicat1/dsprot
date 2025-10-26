# dsprot

This is a decompilation of DS Protect, an antipiracy library for the Nintendo DS. This is version **1.05**. See below for a list of games that use this version, and see other branches for alternate versions.

See [dsdetect](https://github.com/taxicat1/dsdetect) to analyze a ROM file for DS Protect, as the lists here are not comprehensive.

This library is designed to detect if a DS game is running on an emulator or flashcart. What happens after it detects that is up to the game that is integrating it.

The existence, mechanics, and effects of DS Protect have been documented as early as 2009 ([link](https://gbatemp.net/threads/seeking-help-for-anti-piracy-protection-removal.134683/post-1768816), [link](https://sourceforge.net/p/desmume/bugs/979/), [link](https://opentrackers.org/scenerules.org/html/2010_NDSr.html)).

Over 300 DS titles are known to use DS Protect in some form.

For instructions to build the library, see [BUILD.MD](./BUILD.MD).

For documentation of its inner workings, see [FUNCTIONALITY.MD](./doc/FUNCTIONALITY.MD) (also [ENCODING.MD](./doc/ENCODING.MD) and [ASSEMBLY.MD](./doc/ASSEMBLY.MD)).

## Game list

| Serial | Title | Region | Location |
| --- | --- | --- | --- |
| C24J | Phantasy Star 0 | Japan | Static region |
| C3JJ | Layton Kyouju to Saigo no Jikan Ryokou | Japan | Overlay 10 |
| C5YJ | Chocobo to Mahou no Ehon - Majo to Shoujo to 5-Nin no Yuusha | Japan | Static region |
| CCTJ | Cid to Chocobo no Fushigi na Dungeon - Tokiwasure no Meikyuu DS+ | Japan | Static region |
| CT5K | TOEIC DS - Haru 10-Bun Yakjeomgeukbog | Korea | Static region |
| YQUE | Chrono Trigger | USA | Static region |
| YQUJ | Chrono Trigger | Japan | Static region |
| YQUP | Chrono Trigger | Europe | Static region |
