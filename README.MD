# dsprot

This is a decompilation of DS Protect, an antipiracy library for the Nintendo DS. This is likely version 1.20 (unconfirmed), as it appears in localized versions of Pokémon HeartGold and SoulSilver as overlay 123. 

This library is designed to detect if a DS game is running on an emulator or flashcart. What happens after it detects that is up to the game that is integrating it: HeartGold and SoulSilver will leak memory until the game eventually crashes.

Supposedly, at least 500 DS titles use DS Protect in some form.

For instructions to build the library, and integrate it into [pokeheartgold](https://github.com/pret/pokeheartgold/) and match the official ROM, see [BUILD.MD](./BUILD.MD).

For documentation of its inner workings, see [FUNCTIONALITY.MD](./doc/FUNCTIONALITY.MD) (also [ENCODING.MD](./doc/ENCODING.MD) and [ASSEMBLY.MD](./doc/ASSEMBLY.MD)).

## TODO

- Verify it actually works with Wine.
- Decompile the last function (`Encryptor_EncryptFunction` @ https://decomp.me/scratch/I41ac).
- pokeheartgold-specific build can be removed if pokeheartgold is updated.
