# dsprot

This is a decompilation of DS Protect, an antipiracy library for the Nintendo DS. This is version **2.05**. See below for a list of games that use this version, and see other branches for alternate versions.

See [dsdetect](https://github.com/taxicat1/dsdetect) to analyze a ROM file for DS Protect, as the lists here are not comprehensive.

This library is designed to detect if a DS game is running on an emulator or flashcart. What happens after it detects that is up to the game that is integrating it.

The existence, mechanics, and effects of DS Protect have been documented as early as 2009 ([link](https://gbatemp.net/threads/seeking-help-for-anti-piracy-protection-removal.134683/post-1768816), [link](https://sourceforge.net/p/desmume/bugs/979/), [link](https://opentrackers.org/scenerules.org/html/2010_NDSr.html)).

Over 300 DS titles are known to use DS Protect in some form.

For instructions to build the library, see [BUILD.MD](./BUILD.MD).

For documentation of its inner workings, see [FUNCTIONALITY.MD](./doc/FUNCTIONALITY.MD) (also [ENCODING.MD](./doc/ENCODING.MD) and [ASSEMBLY.MD](./doc/ASSEMBLY.MD)).

## Game list

| Serial | Title | Region | Location |
| --- | --- | --- | --- |
| IRDD | Pokemon - Weisse Edition 2 | Germany | Overlay 337 |
| IRDF | Pokemon - Version Blanche 2 | France | Overlay 337 |
| IRDI | Pokemon - Versione Bianca 2 | Italy | Overlay 337 |
| IRDJ | Pokemon - White 2 (v01) | Japan | Overlay 337 |
| IRDK | Pokemon - White Version 2 | Korea | Overlay 337 |
| IRDO | Pokemon - White Version 2 (Europe) | USA | Overlay 337 |
| IRDS | Pokemon - Edicion Blanca 2 | Spain | Overlay 337 |
| IRED | Pokemon - Schwarze Edition 2 | Germany | Overlay 337 |
| IREF | Pokemon - Version Noire 2 | France | Overlay 337 |
| IREI | Pokemon - Versione Nera 2 | Italy | Overlay 337 |
| IREJ | Pokemon - Black 2 (v01) | Japan | Overlay 337 |
| IREK | Pokemon - Black Version 2 | Korea | Overlay 337 |
| IREO | Pokemon - Black Version 2 (Europe) | USA | Overlay 337 |
| IRES | Pokemon - Edicion Negra 2 | Spain | Overlay 337 |
| TCYE | Mama's Combo Pack - Volume 1 | USA | Overlay 0 |
| TCZE | Mama's Combo Pack - Volume 2 | USA | Overlay 3 |
| TDVP | Shin Megami Tensei - Devil Survivor 2 | Europe | Overlay 6 |
| TMDP | Cooking Mama World - ComboPack - Volume 2 | Europe | Overlay 3 |
| TR2E | The Smurfs 2 | USA | Overlay 0 |
| TR2P | The Smurfs 2 | Europe | Overlay 0 |
| UZPD | Lernen mit Pokemon - Tasten-Abenteuer | Germany | Overlay 0 |
| UZPF | Apprends avec Pokemon - A la Conquete du Clavier | France | Overlay 0 |
| UZPP | Learn with Pokemon - Typing Adventure | Europe | Overlay 0 |
| VPYP | Pokemon Conquest | Europe | Overlay 9 |
| VPYT | Pokemon Conquest | USA | Overlay 9 |
