# dsprot

This is a decompilation of DS Protect, an antipiracy library for the Nintendo DS. This is version 2.03/Instant, as it appears in these games (but likely several more):
- Fossil Fighters: Champions (US) as overlay 16
- All Kamen Rider: Rider Generation (Japan) as overlay 0
- Power Pro Kun Pocket 14 (Japam) as overlay 33
- Suite PreCure: Melody Collection (Japan) as overlay 45
- One Piece Gigant Battle 2: Shin Sekai (Japan) as overlay 37

This library is designed to detect if a DS game is running on an emulator or flashcart. If it detects this, it will crash the system.

The existence, mechanics, and effects of DS Protect have been documented as early as 2009 ([link](https://gbatemp.net/threads/seeking-help-for-anti-piracy-protection-removal.134683/post-1768816), [link](https://sourceforge.net/p/desmume/bugs/979/), [link](https://opentrackers.org/scenerules.org/html/2010_NDSr.html)).

Supposedly, at least 500 DS titles use DS Protect in some form.

For instructions to build the library see [BUILD.MD](./BUILD.MD).

For documentation of its inner workings, see [FUNCTIONALITY.MD](./doc/FUNCTIONALITY.MD) (also [ENCODING.MD](./doc/ENCODING.MD) and [ASSEMBLY.MD](./doc/ASSEMBLY.MD)).

## TODO

- Verify it actually works with Wine.
