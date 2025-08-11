# dsprot

This is a decompilation of DS Protect, an antipiracy library for the Nintendo DS. This is version **1.22**. See below for a list of games that use this version, and see other branches for alternate versions.

This library is designed to detect if a DS game is running on an emulator or flashcart. What happens after it detects that is up to the game that is integrating it.

The existence, mechanics, and effects of DS Protect have been documented as early as 2009 ([link](https://gbatemp.net/threads/seeking-help-for-anti-piracy-protection-removal.134683/post-1768816), [link](https://sourceforge.net/p/desmume/bugs/979/), [link](https://opentrackers.org/scenerules.org/html/2010_NDSr.html)).

Over 300 DS titles are known to use DS Protect in some form.

For instructions to build the library, see [BUILD.MD](./BUILD.MD).

For documentation of its inner workings, see [FUNCTIONALITY.MD](./doc/FUNCTIONALITY.MD) (also [ENCODING.MD](./doc/ENCODING.MD) and [ASSEMBLY.MD](./doc/ASSEMBLY.MD)).

## Game list

| Serial | Title | Region | Location |
| --- | --- | --- | --- |
| AZLE | Style Savvy | USA | Overlay 156 |
| AZLP | Nintendo Presents - Style Boutique (v01) | Europe | Overlay 156 |
| B3CJ | Cooking Mama 3 | Japan | Overlay 2 |
| B6XJ | Rockman EXE - Operate Shooting Star | Japan | Overlay 583 |
| BDNJ | Cross Treasures | Japan | Overlay 2 |
| BEBJ | Inazuma Eleven 2 - Kyoui no Shinryakusha - Blizzard | Japan | Overlay 88 |
| BEBJ | Inazuma Eleven 2 - Kyoui no Shinryakusha - Blizzard (v01) | Japan | Overlay 88 |
| BEEJ | Inazuma Eleven 2 - Kyoui no Shinryakusha - Fire | Japan | Overlay 88 |
| BEEJ | Inazuma Eleven 2 - Kyoui no Shinryakusha - Fire (v01) | Japan | Overlay 88 |
| BFPJ | Fresh Pretty Cure! - Asobi Collection | Japan | Overlay 77 |
| BFXE | Final Fantasy - The 4 Heroes of Light | USA | Overlay 0 |
| BFXJ | Hikari no 4 Senshi - Final Fantasy Gaiden | Japan | Overlay 0 |
| BFXP | Final Fantasy - The 4 Heroes of Light | Europe | Overlay 0 |
| BGVJ | Tamagotchi no Narikiri Channel | Japan | Overlay 33 |
| BKCE | America's Test Kitchen - Let's Get Cooking | USA | Overlay 0 |
| BKPJ | Pro Wrestling Kentei DS | Japan | Overlay 0 |
| BO4J | Ochaken no Heya DS 4 - Ochaken Land de Hotto Shiyo | Japan | Overlay 0 |
| BQ3J | Tago Akira no Atama no Taisou - Dai-3-shuu - Fushigi no Kuni no Nazotoki Otogibanashi | Japan | Overlay 1 |
| BQ4J | Tago Akira no Atama no Taisou - Dai-4-shuu - Time Machine no Nazotoki Daibouken | Japan | Overlay 1 |
| BQPJ | KuruKuru Princess - Tokimeki Figure - Mezase! Vancouver | Japan | Overlay 0 |
| BSKJ | Kyokugen Dasshutsu - 9-jikan, 9-nin, 9 no Tobira | Japan | Overlay 0 |
| BWZJ | Wizardry - Inochi no Kusabi | Japan | Overlay 0 |
| BZ2J | Imasugu Tsukaeru Mamechishiki - Quiz Zatsugaku-ou DS | Japan | Overlay 0 |
| CUHJ | Umihara Kawase Shun - Second Edition Kanzenban | Japan | Overlay 0 |
| VPTJ | Power Pro Kun Pocket 12 | Japan | Overlay 30 |
| YLUJ | Last Window - Mayonaka no Yakusoku | Japan | Static region |
| YNRK | Naruto Jilpungjeon - Daenantu! Geurimja Bunsinsul | Korea | Overlay 6 |
| YVIJ | Dragon Quest VI - Maboroshi no Daichi | Japan | Overlay 47 |
