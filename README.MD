# dsprot

This is a decompilation of DS Protect, an antipiracy library for the Nintendo DS. This is version **2.00**. See below for a list of games that use this version, and see other branches for alternate versions.

See [dsdetect](https://github.com/taxicat1/dsdetect) to analyze a ROM file for DS Protect, as the lists here are not comprehensive.

This library is designed to detect if a DS game is running on an emulator or flashcart. What happens after it detects that is up to the game that is integrating it.

The existence, mechanics, and effects of DS Protect have been documented as early as 2009 ([link](https://gbatemp.net/threads/seeking-help-for-anti-piracy-protection-removal.134683/post-1768816), [link](https://sourceforge.net/p/desmume/bugs/979/), [link](https://opentrackers.org/scenerules.org/html/2010_NDSr.html)).

Over 300 DS titles are known to use DS Protect in some form.

For instructions to build the library, see [BUILD.MD](./BUILD.MD).

For documentation of its inner workings, see [FUNCTIONALITY.MD](./doc/FUNCTIONALITY.MD) (also [ENCODING.MD](./doc/ENCODING.MD) and [ASSEMBLY.MD](./doc/ASSEMBLY.MD)).

## Game list

| Serial | Title | Region | Location |
| --- | --- | --- | --- |
| B4KJ | Shoukou Shindan Training DS | Japan | Overlay 0 |
| BA7J | Kaibou Seirigaku DS - Touch de Hirogaru! Jintai no Kouzou to Kinou (v02) | Japan | Overlay 0 |
| BRGJ | Ishin no Arashi - Shippuu Ryoumaden | Japan | Overlay 0 |
| BRZJ | Metal Fight Bayblade - Choujou Kessen! Big Bang Bladers | Japan | Overlay 0 |
| BRZK | Metal Beyblade 2 - Big Bang Bladers | Korea | Overlay 0 |
| BUCJ | Crayon Shin-Chan Shokkugan! Densetsu wo Yobu Omake Daiketsusen!! | Japan | Overlay 17 |
| BWRJ | Momotarou Dentetsu World | Japan | Overlay 2 |
| BZ3J | SaGa 3 - Jikuu no Hasha - Shadow or Light | Japan | Overlay 4 |
| BZMJ | Korg M01 Music Workstation | Japan | Overlay 0 |
| VMMJ | Gokujou!! Mecha Mote Iinchou - MM My Best Friend! | Japan | Overlay 1 |
