# dsprot

This is a decompilation of DS Protect, an antipiracy library for the Nintendo DS. This is version **1.27**. See below for a list of games that use this version, and see other branches for alternate versions.

This library is designed to detect if a DS game is running on an emulator or flashcart. What happens after it detects that is up to the game that is integrating it.

The existence, mechanics, and effects of DS Protect have been documented as early as 2009 ([link](https://gbatemp.net/threads/seeking-help-for-anti-piracy-protection-removal.134683/post-1768816), [link](https://sourceforge.net/p/desmume/bugs/979/), [link](https://opentrackers.org/scenerules.org/html/2010_NDSr.html)).

Over 300 DS titles are known to use DS Protect in some form.

For instructions to build the library, see [BUILD.MD](./BUILD.MD).

For documentation of its inner workings, see [FUNCTIONALITY.MD](./doc/FUNCTIONALITY.MD) (also [ENCODING.MD](./doc/ENCODING.MD) and [ASSEMBLY.MD](./doc/ASSEMBLY.MD)).

## Game list

| Serial | Title | Region | Location |
| --- | --- | --- | --- |
| B2UE | Sports Collection - 15 Sports to Master | USA | Overlay 23 |
| B2UP | Sports Collection - 15 Sports to Master | Europe | Overlay 23 |
| B3DJ | Taiko no Tatsujin DS - Dororon! Yookai Daikessen!! | Japan | Overlay 5 |
| B3RE | Pokemon Ranger - Guardian Signs | USA | Overlay 0 |
| B3RP | Pokemon Ranger - Guardian Signs | Europe | Overlay 0 |
| B3UE | Petz Nursery 2 | USA | Overlay 0 |
| B3UP | Petz - Playschool | Europe | Overlay 0 |
| B3VE | Vampire Moon - The Mystery of the Hidden Sun | USA | Overlay 0 |
| B3VP | Vampire Moon - The Mystery of the Hidden Sun | Europe | Overlay 0 |
| B4TJ | Tetris Party Premium | Japan | Overlay 1 |
| B5KJ | Tenkaichi Sengoku Lovers DS | Japan | Overlay 0 |
| B8RJ | Kamen Rider Battle - Ganbaride Card Battle Taisen | Japan | Overlay 7 |
| BA5P | Marie-Antoinette and the American War of Independence - The Brotherhood of the Wolf | Europe | Overlay 0 |
| BB4J | Battle Spirits DS - Digital Starter | Japan | Overlay 2 |
| BBJJ | Metal Fight Beyblade - Bakushin Susanoh Shuurai! | Japan | Overlay 1 |
| BBUE | Beyblade - Metal Fusion | USA | Overlay 20 |
| BBUP | Beyblade Metal Fusion - Cyber Pegasus | Europe | Overlay 20 |
| BBUY | Beyblade - Metal Fusion (Collector's Edition) | USA | Overlay 20 |
| BE8J | Inazuma Eleven 3 - Sekai e no Chousen!! Spark | Japan | Overlay 123 |
| BEZJ | Inazuma Eleven 3 - Sekai e no Chousen!! Bomber | Japan | Overlay 123 |
| BH6J | TV Anime - Fairy Tail Gekitou! Madoushi Kessen | Japan | Overlay 0 |
| BHXJ | Quiz! Hexagon II | Japan | Overlay 0 |
| BKQK | Pucca Power Up | Korea | Overlay 0 |
| BKSJ | Keshikasu-kun - Battle Castival | Japan | Overlay 36 |
| BM9J | Metal Max 3 | Japan | Overlay 0 |
| BOJJ | One Piece - Gigant Battle | Japan | Overlay 24 |
| BOOE | Okami Den | USA | Overlay 3 |
| BOOJ | Okamiden - Chisaki Taiyou | Japan | Overlay 3 |
| BOOP | Okamiden | Europe | Overlay 3 |
| BOXJ | Love Plus Plus | Japan | Overlay 1 |
| BOYJ | Odoru Daisousasen The Game - Sensuikan ni Sennyuu Seyo! | Japan | Overlay 0 |
| BQ6J | Cocoro no Cocoron | Japan | Overlay 36 |
| BQFJ | Heart Catch PreCure! Oshare Collection | Japan | Overlay 39 |
| BRJJ | Radiant Historia | Japan | Overlay 0 |
| BSKE | Nine Hours, Nine Persons, Nine Doors | USA | Overlay 0 |
| BTUE | Tinker Bell and the Great Fairy Rescue | USA | Overlay 0 |
| BTUJ | Tinker Bell to Yousei no Ie | Japan | Overlay 0 |
| BTUP | Tinker Bell and the Great Fairy Rescue | Europe | Overlay 0 |
| BTUX | Tinker Bell and the Great Fairy Rescue | Europe | Overlay 0 |
| BTUY | Tinker Bell and the Great Fairy Rescue | Europe | Overlay 0 |
| BU9P | Pucca Power Up | Europe | Overlay 0 |
| BUFE | Petz - Puppyz & Kittenz | USA | Overlay 0 |
| BVGE | Petz - Bunnyz Bunch | USA | Overlay 0 |
| BWYJ | Wizardry - Boukyaku no Isan | Japan | Overlay 0 |
| C6HK | Tomicar Hero Rescue Force DS | Korea | Overlay 0 |
| CNSK | Naruto Shippuden - Naruto vs Sasuke | Korea | Overlay 0 |
| IRAD | Pokemon - Weisse Edition | Germany | Overlay 230 |
| IRAF | Pokemon - Version Blanche | France | Overlay 230 |
| IRAI | Pokemon - Versione Bianca | Italy | Overlay 230 |
| IRAJ | Pokemon - White | Japan | Overlay 230 |
| IRAK | Pokemon - White Version | Korea | Overlay 230 |
| IRAO | Pokemon - White Version (Europe) | USA | Overlay 230 |
| IRAS | Pokemon - Edicion Blanca | Spain | Overlay 230 |
| IRBD | Pokemon - Schwarze Edition | Germany | Overlay 230 |
| IRBF | Pokemon - Version Noire | France | Overlay 230 |
| IRBI | Pokemon - Versione Nera | Italy | Overlay 230 |
| IRBJ | Pokemon - Black | Japan | Overlay 230 |
| IRBK | Pokemon - Black Version | Korea | Overlay 230 |
| IRBO | Pokemon - Black Version (Europe) | USA | Overlay 230 |
| IRBS | Pokemon - Edicion Negra | Spain | Overlay 230 |
| VAOE | Crime Lab - Body of Evidence | USA | Overlay 35 |
| VAOP | Crime Lab - Body of Evidence | Europe | Overlay 35 |
| VCDJ | Solatorobo - Sorekara Coda e | Japan | Overlay 4 |
| VETP | 1000 Cooking Recipes from Elle a Table | Europe | Overlay 52 |
| VI2J | Fire Emblem - Shin Monshou no Nazo Hikari to Kage no Eiyuu (v01) | Japan | Overlay 10 |
| VPFV | Phineas and Ferb - Ride Again | Europe | Overlay 5 |
| YBUD | Blue Dragon - Awakened Shadow | Germany | Overlay 15 |
| YBUF | Blue Dragon - Awakened Shadow | France | Overlay 15 |
| YBUI | Blue Dragon - Awakened Shadow | Italy | Overlay 15 |
| YBUP | Blue Dragon - Awakened Shadow | Europe | Overlay 15 |
| YBUS | Blue Dragon - Awakened Shadow | Spain | Overlay 15 |
| YLUP | Last Window - The Secret of Cape West | Europe | Static region |
