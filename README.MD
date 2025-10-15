# dsprot

This is a decompilation of DS Protect, an antipiracy library for the Nintendo DS. This is possibly version **1.00** or **1.02** (unknown). See below for a list of games that use this version, and see other branches for alternate versions.

See [dsdetect](https://github.com/taxicat1/dsdetect) to analyze a ROM file for DS Protect, as the lists here are not comprehensive.

This library is designed to detect if a DS game is running on an emulator or flashcart. What happens after it detects that is up to the game that is integrating it.

The existence, mechanics, and effects of DS Protect have been documented as early as 2009 ([link](https://gbatemp.net/threads/seeking-help-for-anti-piracy-protection-removal.134683/post-1768816), [link](https://sourceforge.net/p/desmume/bugs/979/), [link](https://opentrackers.org/scenerules.org/html/2010_NDSr.html)).

Over 300 DS titles are known to use DS Protect in some form.

For instructions to build the library, see [BUILD.MD](./BUILD.MD).

For documentation of its inner workings, see [FUNCTIONALITY.MD](./doc/FUNCTIONALITY.MD) (also [ENCODING.MD](./doc/ENCODING.MD) and [ASSEMBLY.MD](./doc/ASSEMBLY.MD)).

## Game list

| Serial | Title | Region | Location |
| --- | --- | --- | --- |
| ANMK | Maeilmaeil Deoukdeo! DS Dunoe Training | Korea | Static region |
| YFTK | Pokemon Mystery Dungeon - Explorers of Time | Korea | Static region |
| YFYK | Pokemon Mystery Dungeon - Explorers of Darkness | Korea | Static region |
| YV5E | Dragon Quest V - Hand of the Heavenly Bride | USA | Static region |
| YV5J | Dragon Quest V - Tenkuu no Hanayome | Japan | Static region |
| YV5P | Dragon Quest - The Hand of the Heavenly Bride | Europe | Static region |
| YVKK | DS Vitamin - Health Food Guide! | Korea | Static region |

