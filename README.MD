# dsprot

This is a decompilation of DS Protect, an antipiracy library for the Nintendo DS. This is version **1.23z**. This is an apparent customized version of 1.23 specifically for The Legend of Zelda: Spirit Tracks. The only differences between this version and the base 1.23 are changed encryption keys and obfuscation values. See below for the list of releases that use this version, and see other branches for alternate versions.

This library is designed to detect if a DS game is running on an emulator or flashcart. What happens after it detects that is up to the game that is integrating it.

The existence, mechanics, and effects of DS Protect have been documented as early as 2009 ([link](https://gbatemp.net/threads/seeking-help-for-anti-piracy-protection-removal.134683/post-1768816), [link](https://sourceforge.net/p/desmume/bugs/979/), [link](https://opentrackers.org/scenerules.org/html/2010_NDSr.html)).

Over 300 DS titles are known to use DS Protect in some form.

For instructions to build the library, see [BUILD.MD](./BUILD.MD).

For documentation of its inner workings, see [FUNCTIONALITY.MD](./doc/FUNCTIONALITY.MD) (also [ENCODING.MD](./doc/ENCODING.MD) and [ASSEMBLY.MD](./doc/ASSEMBLY.MD)).

## Game list

| Serial | Title | Region | Location |
| --- | --- | --- | --- |
| BKIE | The Legend of Zelda - Spirit Tracks | USA | Overlay 1 |
| BKIJ | Zelda no Densetsu - Daichi no Kiteki | Japan | Overlay 1 |
| BKIP | The Legend of Zelda - Spirit Tracks | Europe | Overlay 1 |
