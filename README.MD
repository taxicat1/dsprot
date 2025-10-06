# dsprot

This is a decompilation of DS Protect, an antipiracy library for the Nintendo DS. This is version **1.25**. See below for a list of games that use this version, and see other branches for alternate versions.

See [dsdetect](https://github.com/taxicat1/dsdetect) to analyze a ROM file for DS Protect, as the lists here are not comprehensive.

This library is designed to detect if a DS game is running on an emulator or flashcart. What happens after it detects that is up to the game that is integrating it.

The existence, mechanics, and effects of DS Protect have been documented as early as 2009 ([link](https://gbatemp.net/threads/seeking-help-for-anti-piracy-protection-removal.134683/post-1768816), [link](https://sourceforge.net/p/desmume/bugs/979/), [link](https://opentrackers.org/scenerules.org/html/2010_NDSr.html)).

Over 300 DS titles are known to use DS Protect in some form.

For instructions to build the library, see [BUILD.MD](./BUILD.MD).

For documentation of its inner workings, see [FUNCTIONALITY.MD](./doc/FUNCTIONALITY.MD) (also [ENCODING.MD](./doc/ENCODING.MD) and [ASSEMBLY.MD](./doc/ASSEMBLY.MD)).

## Game list

| Serial | Title | Region | Location |
| --- | --- | --- | --- |
| B3XE | River City Soccer Hooligans | USA | Overlay 2 |
| B3XJ | Kunio-kun no Chou Nekketsu! - Soccer League Plus - World Hyper Cup Hen | Japan | Overlay 2 |
| B42J | Pet Shop Monogatari DS 2 | Japan | Overlay 16 |
| BCKJ | Kochira Katsushika Ku Kameari Kouen Mae Hashutsujo - Kateba Tengoku! Makereba Jigoku! | Japan | Overlay 0 |
| BCXJ | Kodawari Saihai Simulation - Ochanoma Pro Yakyuu DS - 2010 Nendo Ban | Japan | Overlay 11 |
| BF2J | Pro Yakyuu Famista DS 2010 | Japan | Static region |
| BKKJ | Keroro RPG - Kishi to Musha to Densetsu no Kaizoku | Japan | Static region |
| BLEJ | Digimon Story - Lost Evolution | Japan | Overlay 4 |
| BQUJ | Minna no Suizokukan | Japan | Overlay 0 |
| BRYJ | Hudson x GReeeeN - Live! DeeeeS! | Japan | Static region |
| CA5E | Again - Interactive Crime Novel | USA | Overlay 0 |
| CZZK | Let's Play English Word with Picture | Korea | Overlay 0 |
| V29J | RPG Tkool DS | Japan | Overlay 0 |
| YMPK | MapleStory DS | Korea | Overlay 107 |
