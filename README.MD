# dsprot

This is a decompilation of DS Protect, an antipiracy library for the Nintendo DS. This is version **2.03 Instant**. See below for a list of games that use this version, and see other branches for alternate versions.

See [dsdetect](https://github.com/taxicat1/dsdetect) to analyze a ROM file for DS Protect, as the lists here are not comprehensive.

This library is designed to detect if a DS game is running on an emulator or flashcart. If it detects this, it will crash the system.

The existence, mechanics, and effects of DS Protect have been documented as early as 2009 ([link](https://gbatemp.net/threads/seeking-help-for-anti-piracy-protection-removal.134683/post-1768816), [link](https://sourceforge.net/p/desmume/bugs/979/), [link](https://opentrackers.org/scenerules.org/html/2010_NDSr.html)).

Over 300 DS titles are known to use DS Protect in some form.

For instructions to build the library, see [BUILD.MD](./BUILD.MD).

For documentation of its inner workings, see [FUNCTIONALITY.MD](./doc/FUNCTIONALITY.MD) (also [ENCODING.MD](./doc/ENCODING.MD) and [ASSEMBLY.MD](./doc/ASSEMBLY.MD)).

## Game list

| Serial | Title | Region | Location |
| --- | --- | --- | --- |
| B6KP | Tinker Bell - 2 Disney Games | Europe | Overlay 50 |
| TAKJ | All Kamen Rider - Rider Generation | Japan | Overlay 0 |
| TBQJ | Bakuman - Mangaka e no Michi | Japan | Overlay 10 |
| TGBJ | One Piece - Gigant Battle 2 - Shin Sekai | Japan | Overlay 37 |
| TGKJ | Kaizoku Sentai Gokaiger - Atsumete Henshin! 35 Sentai! | Japan | Overlay 4 |
| TPQJ | Suite PreCure - Melody Collection | Japan | Overlay 45 |
| VDEE | Fossil Fighters - Champions | USA | Overlay 16 |
| VP4J | Power Pro Kun Pocket 14 | Japan | Overlay 33 |
| VPYJ | Pokemon Plus - Nobunaga no Yabou | Japan | Overlay 8 |
