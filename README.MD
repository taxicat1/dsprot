# dsprot

This is a decompilation of DS Protect, an antipiracy library for the Nintendo DS. This is version 2.05, as it appears in these games (but likely several more):
- Pokémon Black 2 + Pokémon White 2 (US and Japan) as overlay 337
- Pokemon Conquest (US and Japan) as overlay 9
- Learn with Pokémon: Typing Adventure (US and Japan) as overlay 0
- The Smurfs 2 (US) as overlay 0

This library is designed to detect if a DS game is running on an emulator or flashcart. What happens after it detects that is up to the game that is integrating it.

The existence, mechanics, and effects of DS Protect have been documented as early as 2009 ([link](https://gbatemp.net/threads/seeking-help-for-anti-piracy-protection-removal.134683/post-1768816), [link](https://sourceforge.net/p/desmume/bugs/979/), [link](https://opentrackers.org/scenerules.org/html/2010_NDSr.html)).

Supposedly, at least 500 DS titles use DS Protect in some form.

For instructions to build the library see [BUILD.MD](./BUILD.MD).

For documentation of its inner workings, see [FUNCTIONALITY.MD](./doc/FUNCTIONALITY.MD) (also [ENCODING.MD](./doc/ENCODING.MD) and [ASSEMBLY.MD](./doc/ASSEMBLY.MD)).

## TODO

- Verify it actually works with Wine.
