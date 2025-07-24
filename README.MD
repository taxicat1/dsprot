# dsprot

This is a decompilation of DS Protect, an antipiracy library for the Nintendo DS. This is likely version 1.23 (unconfirmed), as it appears in localized versions of Pokémon HeartGold and SoulSilver as overlay 123. 

See other branches for alternate versions.

This library is designed to detect if a DS game is running on an emulator or flashcart. What happens after it detects that is up to the game that is integrating it: HeartGold and SoulSilver will leak memory until the game eventually crashes.

The existence, mechanics, and effects of DS Protect have been documented as early as 2009 ([link](https://gbatemp.net/threads/seeking-help-for-anti-piracy-protection-removal.134683/post-1768816), [link](https://sourceforge.net/p/desmume/bugs/979/), [link](https://opentrackers.org/scenerules.org/html/2010_NDSr.html)).

Supposedly, at least 500 DS titles use DS Protect in some form.

For instructions to build the library, and integrate it into [pokeheartgold](https://github.com/pret/pokeheartgold/) and match the official ROM, see [BUILD.MD](./BUILD.MD).

For documentation of its inner workings, see [FUNCTIONALITY.MD](./doc/FUNCTIONALITY.MD) (also [ENCODING.MD](./doc/ENCODING.MD) and [ASSEMBLY.MD](./doc/ASSEMBLY.MD)).

## TODO

- Verify it actually works with Wine.
- Decompile the last function (`Encryptor_EncryptFunction` @ https://decomp.me/scratch/I41ac).
- pokeheartgold-specific build can be removed if pokeheartgold is updated.
