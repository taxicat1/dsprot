# dsprot

This is a decompilation of DS Protect, an antipiracy library for the Nintendo DS. This is version 2.01/Instant, as it appears in these games (but likely several more):
- Golden Sun: Dark Dawn (US) as overlay 335
- Fossil Fighters: Champions (Japan) as overlay 16
- Puyo Puyo!! 20th Anniversary (Japan) as overlay 16
- Treasure Report: Kikai Jikake no Isan (Japan) as overlay 18
- Shin Megami Tensei - Devil Survivor 2 (US and Japan) as overlay 5
- Powerful Golf (Japan) as overlay 3
- Kaijuu Busters Powered (Japan) as overlay 7
- Kimi ni Todoke - Tsutaeru Kimochi (Japan) as overlay 3
- Mabeop Cheonjamun DS 2: Choehoui Hanjamabeop (Japan) as overlay 29
- Minna to Kimi no Piramekino! (Japan) as overlay 0

This library is designed to detect if a DS game is running on an emulator or flashcart. If it detects this, it will crash the system.

The existence, mechanics, and effects of DS Protect have been documented as early as 2009 ([link](https://gbatemp.net/threads/seeking-help-for-anti-piracy-protection-removal.134683/post-1768816), [link](https://sourceforge.net/p/desmume/bugs/979/), [link](https://opentrackers.org/scenerules.org/html/2010_NDSr.html)).

Supposedly, at least 500 DS titles use DS Protect in some form.

For instructions to build the library see [BUILD.MD](./BUILD.MD).

For documentation of its inner workings, see [FUNCTIONALITY.MD](./doc/FUNCTIONALITY.MD) (also [ENCODING.MD](./doc/ENCODING.MD) and [ASSEMBLY.MD](./doc/ASSEMBLY.MD)).

## TODO

- Verify it actually works with Wine.
