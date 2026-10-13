# ফরেনসিক ও রিভার্স ইঞ্জিনিয়ারিং রিপোর্ট: `Data_xe.bin` এবং মাল্টি-ইনস্টলার গেম আর্কিটেকচার

[**[English Version]**](file:///F:/Project/skill/decoder/docs/DATA_XE_BIN_FORENSIC_ANALYSIS.md) | [**[মূল ফরেনসিক রিপোর্ট]**](file:///F:/Project/skill/decoder/docs/README_BN.md)

---

## ১. নির্বাহী সারসংক্ষেপ (Executive Summary)

টার্গেট প্যাকেজ ফোল্ডার:
`C:\Users\Administrator\Downloads\_Oceanofgames.com_Closure\Closure`

আমরা ফোল্ডারের ফাইল **`Data_xe.bin`** (১,৮৭৬,৫৮১ বাইট) বিশ্লেষণ করেছি এবং অনুসন্ধান করেছি কেন সাধারণ এক্সট্রাক্টর বা পূর্ববর্তী SFX আনপ্যাকার (`standalone_extractor.exe`) এই ফাইলের উপর কাজ করেনি।

### মূল ফরেনসিক আবিষ্কার:

১. **`Data_xe.bin` আসলে একটি ছদ্মবেশী এক্সিকিউটেবল ফাইল (PE32)**:
   - যদিও ফাইলটির এক্সটেনশন `.bin`, ফাইলের শুরুতে রয়েছে `MZP\x00` ম্যাজিক হেডার।
   - এটি **Borland Delphi** দিয়ে কম্পাইল করা **Inno Setup 5.4.3** এর একটি ৩২-বিট উইন্ডোজ GUI পোর্টেবল এক্সিকিউটেবল (PE32)।

২. **আসল উৎস (Data_xe.bin ফাইলের ভেতরে কোনো ভাইরাস নেই)**:
   - ফাইলের অভ্যন্তরীণ PE রিসোর্স মেটাডেটা যাচাই করে নিশ্চিত হওয়া গেছে এটি একটি **আসল ও নির্ভেজাল গেম ইনস্টলার**:
     - **প্রোডাক্টের নাম**: `Closure`
     - **কোম্পানির নাম**: `R.G. Origami` (বিখ্যাত রাশিয়ান গেম রিপ্যাক গ্রুপ)
     - **ফাইলের বিবরণ**: `Closure Setup`
     - **মন্তব্য**: `This installation was built with Inno Setup.`
   - স্ট্যাটিক স্ট্রিং এবং ইমপোর্ট অ্যানালাইসিসে প্রমাণিত হয়েছে যে `Data_xe.bin` এর ভেতর কোনো ম্যালওয়্যার, ট্রোজান বা পারসিস্টেন্স কোড নেই।

৩. **কেন আগের টুল কাজ করেনি?**:
   - `standalone_extractor.exe` তৈরি করা হয়েছিল বিশেষভাবে **Advanced Installer SFX** কনটেইনারের জন্য (যার ফাইলের শেষে `ADVINSTSFX` ট্রেলার এবং XOR 0xFF ইনভার্ট করা 7z স্ট্রিম থাকে)।
   - `Data_xe.bin` সম্পূর্ণ ভিন্ন ইঞ্জিনে তৈরি: **Inno Setup + ISDone.dll + FreeArc**! এতে কোনো `ADVINSTSFX` ট্রেলার নেই।
   - পূর্বের `safe_extractor.py` স্ক্রিপ্টে ধরে নেওয়া হয়েছিল যেকোনো `.bin` ফাইলই Setup Factory প্যাকেজ।

৪. **OceanofGames এর ছদ্মবেশ ও প্রতারণার কৌশল (Bait-and-Switch)**:
   - আসল গেম রিপ্যাকে এই ফাইলটির আসল নাম ছিল **`Setup.exe`**।
   - OceanofGames ম্যালওয়্যার ডিস্ট্রিবিউটররা ইচ্ছাকৃতভাবে `Setup.exe` এর নাম পরিবর্তন করে **`Data_xe.bin`** (`_xe` = `.exe`) রেখে দেয়, যাতে উইন্ডোজে ডাবল-ক্লিক করলে গেম ইনস্টলার রান না হয়।
   - ফোল্ডারের অন্যান্য ফাইলও এই সত্য প্রমাণ করে:
     - `autorun.inf`: `OPEN=Setup.exe`
     - `CheckSums_xe.txt`: `Setup.exe`
   - আসল ইনস্টলারকে ব্লক করে আক্রমণকারীরা ভিকটিমকে প্রতারণামূলক `Read me - How To Install.txt` অনুসরণে বাধ্য করে ম্যালওয়্যার ড্রপার রান করায়:
     - `Step 1 - Disable Defender.exe` (ডিফেন্ডার নিষ্ক্রিয় করার টুল)
     - `Step 3 - Setup_Install_Game.exe` (Advanced Installer SFX ট্রোজান ড্রপার, যা সিস্টেমে `NSudo.exe`, রুটকিট ও ডিফেন্ডার ডিলিট করার স্ক্রিপ্ট চালায়)।

---

## ২. বাইনারি পরিচিতি ও মেটাডেটা

| বৈশিষ্ট্য | মান |
| :--- | :--- |
| **ফাইলের পাথ** | `C:\Users\Administrator\Downloads\_Oceanofgames.com_Closure\Closure\Data_xe.bin` |
| **আসল নাম** | `Setup.exe` (`autorun.inf` এবং `CheckSums_xe.txt` অনুযায়ী) |
| **ফাইলের সাইজ** | ১,৮৭৬,৫৮১ বাইট (~১.৭৯ মেগাবাইট) |
| **ফরম্যাট** | Portable Executable (PE32, GUI, 32-bit x86 Little-Endian) |
| **কম্পাইলার / ইঞ্জিন** | Borland Delphi / Inno Setup 5.4.3 |
| **MD5** | `b93dee0335872dacb6e5374c9fbbbdf1` |
| **SHA-256** | `8472f8b06c7bb8e307feb10d44c38596da598569eb74c536e2a3e0c1875e83d2` |
| **সাবসিস্টেম** | Win32 GUI (`2`) |
| **এন্ট্রি পয়েন্ট** | `0x00409C14` |

---

## ৩. Inno Setup + ISDone রিপ্যাক আর্কিটেকচার বিশ্লেষণ

`Data_xe.bin` এর ভেতরে গেমের ফাইল সরাসরি সংরক্ষণ করা থাকে না। এর পরিবর্তে রাশিয়ান রিপ্যাকাররা ভেতরে বিশেষ আনপ্যাকিং লাইব্রেরি এম্বেড করে রাখে:

### এম্বেডেড হেল্পার লাইব্রেরি কার্ভিং:

আপগ্রেড করা `safe_extractor.py` স্ট্যাটিক কার্ভারের মাধ্যমে কোনো কোড এক্সিকিউট না করেই ১০টি এম্বেডেড লাইব্রেরি নিরাপদে বের করে আনা হয়েছে:

```
unpacker_toolkit/
├── botva2.dll             # GUI স্কিনিং ও স্বচ্ছ বাটন ইঞ্জিন (South.Tver)
├── unarc.dll              # FreeArc হাই-কম্প্রেশন ডিকম্প্রেশন ইঞ্জিন
├── ISDone.dll             # Inno Setup ব্যাকগ্রাউন্ড আনপ্যাকিং ম্যানেজার (FragSoft / ProFrager)
├── CLS-Precomp.dll        # Precomp ডিকম্প্রেশন প্লাগইন
├── packjpg_dll.dll        # JPEG স্ট্রিম ডিকম্প্রেশন ফিল্টার
├── packJPG_DLL.dll        # সেকেন্ডারি packJPG প্লাগইন
├── zlib1.dll              # স্ট্যান্ডার্ড zlib 1.2.3 কম্প্রেশন লাইব্রেরি
├── CLS-srep.dll           # Super-REPresentation (SREP) ডিকম্প্রেশন ফিল্টার
├── facompress.dll         # FreeArc কম্প্রেশন স্ট্রিম হেল্পার
└── embedded_0x11D63D.exe  # স্ট্যান্ডঅ্যালোন precomp এক্সিকিউটেবল (UPX প্যাকড)
```

---

## ৪. সঙ্গী গেম ডেটা পেলোড (`data 1.bin` - `data 4.bin`)

*Closure* গেমের আসল ডেটা একই ফোল্ডারে ৪টি এক্সটার্নাল আর্কাইভে সংরক্ষিত:

| ফাইলের নাম | সাইজ (বাইট) | হেডার ম্যাজিক | শনাক্তকৃত ফরম্যাট |
| :--- | :--- | :--- | :--- |
| `data 1.bin` | ১০৭,৩২৬,৩৫২ | `41 72 43 01` (`ArC\x01`) | FreeArc Archive Slice 1 |
| `data 2.bin` | ১০২,৭৩৬,৩৮৯ | `41 72 43 01` (`ArC\x01`) | FreeArc Archive Slice 2 |
| `data 3.bin` | ১৩,০৬৮,২১৬ | `41 72 43 01` (`ArC\x01`) | FreeArc Archive Slice 3 |
| `data 4.bin` | ৩,৪৫৫,৭৯৩ | `41 72 43 01` (`ArC\x01`) | FreeArc Archive Slice 4 |
| **মোট গেম ভলিউম** | **২২৬,৫৮৬,৭৫০ (~২১৬.০৯ মেগাবাইট)** | — | **সম্পূর্ণ নির্ভেজাল গেম ফাইল** |

সাধারণ ইনস্টলেশনের সময় `Data_xe.bin` (`Setup.exe`) ব্যাকগ্রাউন্ডে `ISDone.dll` এবং `unarc.dll` লোড করে এই ৪টি FreeArc ফাইল থেকে গেম ডেটা এক্সট্রাক্ট করে।

---

## ৫. মাল্টি-ইঞ্জিন গেম ইনস্টলার শনাক্তকরণ ম্যাট্রিক্স

বিভিন্ন গেম কোম্পানি ও রিপ্যাক গ্রুপ ভিন্ন ভিন্ন ইনস্টলার ইঞ্জিন ব্যবহার করে:

| ইনস্টলার টাইপ | শনাক্তকরণ হেডার / সিগনেচার | হ্যান্ডলিং ও এক্সট্রাকশন পদ্ধতি |
| :--- | :--- | :--- |
| **Advanced Installer SFX** | ফাইলের শেষে `ADVINSTSFX` ট্রেলার | প্রথম ৫১২ বাইট XOR 0xFF রিভার্স করে ইন-মেমোরি 7z আনপ্যাক করা হয় (`decoder.dll` / `standalone_extractor.exe`)। |
| **Inno Setup + FreeArc** | `Inno Setup Setup Data` ও `ArC\x01` | PE মেটাডেটা পড়া হয়, এম্বেডেড `unarc.dll` কার্ভ করা হয় এবং FreeArc স্লাইস আনপ্যাক করা হয়। |
| **Setup Factory** | `\xe0\xe0\xe1\xe1...` সিগনেচার | `sfextract` দিয়ে রানটাইম ওভারলে আনপ্যাক করে `irsetup.exe` ও আসল গেম ফাইল বের করা হয়। |
| **NSIS (Nullsoft)** | `NullsoftInst` সিগনেচার | 7-Zip বা NSIS স্ক্রিপ্ট পার্সার দিয়ে আনপ্যাক করা হয়। |

---

## ৬. নিরাপদ ব্যবহার ও ইনস্টলেশন নির্দেশিকা

### ধাপ ১: প্যাকেজ স্ট্যাটিকভাবে স্ক্যান ও বিশ্লেষণ
আপগ্রেড করা `safe_extractor.py` চালান:
```cmd
python F:\Project\skill\decoder\src\tools\safe_extractor.py "C:\Users\Administrator\Downloads\_Oceanofgames.com_Closure\Closure" -o "F:\Project\skill\decoder\samples\closure_out"
```

### ধাপ ২: ম্যালওয়্যার ছাড়াই আসল গেম ইনস্টল করা
OceanofGames এর কোনো ম্যালওয়্যার এক্সিকিউট না করে আসল গেম চালাতে:
১. **কখনোই** `Step 0`, `Step 1`, বা `Step 3` রান করবেন না।
২. একটি সুরক্ষিত পরিবেশে (যেমন **Windows Sandbox** বা অফলাইন ভার্চুয়াল মেশিন):
   - `Data_xe.bin` ফাইলটির নাম পরিবর্তন করে পুনরায় **`Setup.exe`** করুন।
   - `Setup.exe` রান করুন।
   - R.G. Origami এর উইজার্ড সম্পূর্ণ স্বাভাবিকভাবে `data 1.bin` থেকে `data 4.bin` আনপ্যাক করে গেমটি ইনস্টল করে দেবে।
