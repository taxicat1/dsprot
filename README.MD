# dsprot

This is a decompilation of DS Protect, an antipiracy library for the Nintendo DS. This is version **1.08**. See below for a list of games that use this version, and see other branches for alternate versions.

See [dsdetect](https://github.com/taxicat1/dsdetect) to analyze a ROM file for DS Protect, as the lists here are not comprehensive.

This library is designed to detect if a DS game is running on an emulator or flashcart. What happens after it detects that is up to the game that is integrating it.

The existence, mechanics, and effects of DS Protect have been documented as early as 2009 ([link](https://gbatemp.net/threads/seeking-help-for-anti-piracy-protection-removal.134683/post-1768816), [link](https://sourceforge.net/p/desmume/bugs/979/), [link](https://opentrackers.org/scenerules.org/html/2010_NDSr.html)).

Over 300 DS titles are known to use DS Protect in some form.

For instructions to build the library, see [BUILD.MD](./BUILD.MD).

For documentation of its inner workings, see [FUNCTIONALITY.MD](./doc/FUNCTIONALITY.MD) (also [ENCODING.MD](./doc/ENCODING.MD) and [ASSEMBLY.MD](./doc/ASSEMBLY.MD)).

## Game list

| Serial | Title | Region | Location |
| --- | --- | --- | --- |
| A3YK | Sonic Rush Adventures | Korea | Overlay 6 |
| B89J | Pro Yakyuu Team o Tsukurou! 2 | Japan | Static region |
| BYOJ | Puyo Puyo 7 | Japan | Overlays 9, 12, 14, 15, 19 |
| C29J | Pro Yakyuu Famista DS 2009 | Japan | Static region |
| C36J | Sloane to MacHale no Nazo no Story | Japan | Overlay 0 |
| C4WK | Princess Bakery | Korea | Overlay 0 |
| CBEJ | Saibanin Suiri Game - Yuuzai x Muzai | Japan | Static region |
| YG4K | Genso Suikoden Tierkreis | Korea | Overlay 2 |
| YKGJ | Kingdom Hearts - 358/2 Days (Rev 0) | Japan | Overlay 28 |
| YNOK | Magic Hanja 1000 DS | Korea | Overlay 90 |
| YRBK | Ragnarok DS | Korea | Overlay 64 |
