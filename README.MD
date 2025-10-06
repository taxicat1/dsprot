# dsprot

This is a decompilation of DS Protect, an antipiracy library for the Nintendo DS. This is version **1.20**. See below for a list of games that use this version, and see other branches for alternate versions.

See [dsdetect](https://github.com/taxicat1/dsdetect) to analyze a ROM file for DS Protect, as the lists here are not comprehensive.

This library is designed to detect if a DS game is running on an emulator or flashcart. What happens after it detects that is up to the game that is integrating it.

The existence, mechanics, and effects of DS Protect have been documented as early as 2009 ([link](https://gbatemp.net/threads/seeking-help-for-anti-piracy-protection-removal.134683/post-1768816), [link](https://sourceforge.net/p/desmume/bugs/979/), [link](https://opentrackers.org/scenerules.org/html/2010_NDSr.html)).

Over 300 DS titles are known to use DS Protect in some form.

For instructions to build the library, see [BUILD.MD](./BUILD.MD).

For documentation of its inner workings, see [FUNCTIONALITY.MD](./doc/FUNCTIONALITY.MD) (also [ENCODING.MD](./doc/ENCODING.MD) and [ASSEMBLY.MD](./doc/ASSEMBLY.MD)).

## Game list

| Serial | Title | Region | Location |
| --- | --- | --- | --- |
| B2QJ | Sloane to MacHale no Nazo no Story 2 | Japan | Overlay 0 |
| B74J | Nanashi no Game Me | Japan | Overlay 0 |
| BELJ | Element Hunters | Japan | Overlay 0 |
| BELK | Element Hunters | Korea | Overlay 0 |
| BETJ | Nihon Keizai Shinbunsha Kanshuu - Mono ya Okane no Shikumi DS | Japan | Overlay 0 |
| BHQJ | Otona no Renai Shousetsu - DS Harlequin Selection | Japan | Overlay 9 |
| BIMJ | Iron Master - The Legendary Blacksmith | Japan | Overlay 0 |
| BKTJ | Kimi ni Todoke - Sodateru Omoi | Japan | Static region |
| BOKJ | Ookami to Koushinryou - Umi o Wataru Kaze | Japan | Overlay 0 |
| C24E | Phantasy Star 0 | USA | Static region |
| C24P | Phantasy Star 0 | Europe | Static region |
| C2VJ | Tsukibito | Japan | Static region |
| C2YJ | SupaRobo Gakuen | Japan | Static region |
| CDOK | Iron Master - The Legendary Blacksmith | Korea | Overlay 0 |
| CKDJ | Kindaichi Shonen no Jikenbo - Akuma no Satsujin Koukai | Japan | Static region |
| CLJE | Mario & Luigi - Bowser's Inside Story | USA | Overlay 138 |
| CLJP | Mario & Luigi - Bowser's Inside Story | Europe | Overlay 138 |
| IPGJ | Pokemon - SoulSilver | Japan | Overlay 122 |
| IPKJ | Pokemon - HeartGold | Japan | Overlay 122 |
| VIMJ | The Idolmaster - Dearly Stars | Japan | Overlay 0 |
| VKGE | Korg DS-10+ Synthesizer | USA | Overlay 0 |
| VKGJ | Korg DS-10+ Synthesizer | Japan | Overlay 0 |
| VKPJ | Korg DS-10+ Synthesizer Limited Edition | Japan | Overlay 0 |
| YBUE | Blue Dragon - Awakened Shadow | USA | Overlay 15 |
| YBUJ | Blue Dragon - Ikai no Kyojuu | Japan | Overlay 15 |
| YE9K | Jeoldaeuwi - Yeongdaneo 1900 DS | Korea | Static region |
| YEOK | Jeoldaepilyo - Yeongsukeo 1000 DS | Korea | Static region |
| YRCK | Zzang-Gu Cinema Land - Chalkac Chalkac Daesodong | Korea | Overlay 0 |
