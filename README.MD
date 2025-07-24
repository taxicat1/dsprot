# dsprot

This is a decompilation of DS Protect, an antipiracy library for the Nintendo DS. This is possibly a version between 1.05 and 1.07 (unconfirmed), as it appears in the game スローンとマクヘールの謎の物語 / Surōn to Makuhēru no Nazo no Sutōrī / Sloane to MacHale no Nazo no Story as overlay 0.

This library is designed to detect if a DS game is running on an emulator or flashcart. What happens after it detects that is up to the game that is integrating it: Surōn to Makuhēru no Nazo no Sutōrī will repeatedly quit from the game back to the title screen.

The existence, mechanics, and effects of DS Protect have been documented as early as 2009 ([link](https://gbatemp.net/threads/seeking-help-for-anti-piracy-protection-removal.134683/post-1768816), [link](https://sourceforge.net/p/desmume/bugs/979/), [link](https://opentrackers.org/scenerules.org/html/2010_NDSr.html)).

Supposedly, at least 500 DS titles use DS Protect in some form.

For instructions to build the library see [BUILD.MD](./BUILD.MD).

For documentation of its inner workings, see [FUNCTIONALITY.MD](./doc/FUNCTIONALITY.MD) (also [ENCODING.MD](./doc/ENCODING.MD) and [ASSEMBLY.MD](./doc/ASSEMBLY.MD)).

## TODO

- Verify it actually works with Wine.
