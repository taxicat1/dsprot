# dsprot

This is a decompilation of DS Protect, an antipiracy library for the Nintendo DS. This is allegedly a customized version of version 1.23 (unconfirmed) made specifically for The Legend of Zelda: Spirit Tracks, where it appears in overlay 1. The only differences between this version and the base 1.23 are changed encryption keys and obfuscation values.

This library is designed to detect if a DS game is running on an emulator or flashcart. What happens after it detects that is up to the game that is integrating it: Spirit Tracks will hide the UI for controlling the train, making the game impossible to play.

The existence, mechanics, and effects of DS Protect have been documented as early as 2009 ([link](https://gbatemp.net/threads/seeking-help-for-anti-piracy-protection-removal.134683/post-1768816), [link](https://sourceforge.net/p/desmume/bugs/979/), [link](https://opentrackers.org/scenerules.org/html/2010_NDSr.html)).

Supposedly, at least 500 DS titles use DS Protect in some form.

For instructions to build the library, see [BUILD.MD](./BUILD.MD).

For documentation of its inner workings, see [FUNCTIONALITY.MD](./doc/FUNCTIONALITY.MD) (also [ENCODING.MD](./doc/ENCODING.MD) and [ASSEMBLY.MD](./doc/ASSEMBLY.MD)).

## TODO

- Verify it actually works with Wine.
- Decompile the last function (`Encryptor_EncryptFunction` @ https://decomp.me/scratch/I41ac).
