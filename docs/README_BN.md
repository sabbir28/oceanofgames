# ম্যালওয়্যার ফরেনসিক্স এবং রিভার্স ইঞ্জিনিয়ারিং রিপোর্ট: Decoder.dll ও SFX ড্রপার বিশ্লেষণ

[**[English Version / ইংরেজি সংস্করণ]**](../README.md) | [**[Data_xe.bin ও মাল্টি-ইনস্টলার বিশ্লেষণ (বাংলা)]**](file:///F:/Project/skill/decoder/docs/DATA_XE_BIN_FORENSIC_ANALYSIS_BN.md) | [**[কল অ্যানালাইসিস রিপোর্ট (বাংলা)]**](file:///F:/Project/skill/decoder/docs/DECODER_CALL_ANALYSIS_BN.md) | [**[Call Analysis Report (English)]**](file:///F:/Project/skill/decoder/docs/DECODER_CALL_ANALYSIS.md)

---

## ১. সারসংক্ষেপ ও নিরাপত্তা প্রেক্ষিত (Executive Summary & Security Context)

এই রিপোজিটরিতে **`Decoder.dll`** ফাইলের রিভার্স ইঞ্জিনিয়ারিং বিশ্লেষণ, এর সমতুল্য ক্লিন-রুম সি/সি++ (C/C++) রি-ইমপ্লিমেন্টেশন এবং নিরাপদ এক্সট্রাকশন টুল সংরক্ষণ করা হয়েছে।

`Decoder.dll` ফাইলটি একটি ক্ষতিকারক/সন্দেহজনক ট্রোজানাইজড ইনস্টলার প্যাকেজ (`Step 3 - Setup_Install_Game.exe`, যা "OceanofGames" এর ব্যানারে ছড়ানো হয়েছিল) থেকে উদ্ধার ও বিশ্লেষণ করা হয়েছে। আক্রমণকারীরা প্রায়শই জনপ্রিয় গেম বা সফটওয়্যার রিপ্যাকেজ করতে Advanced Installer SFX কন্টেইনার ব্যবহার করে, যার ভেতর মূল সফটওয়্যারের আড়ালে ক্ষতিকারক পেলোড (যেমন: পারসিস্টেন্স স্ক্রিপ্ট, প্রিভিলেজ এসকেলেশন টুলস, ম্যালওয়্যার ড্রপার ইত্যাদি) লুকিয়ে রাখা হয়।

### প্রধান ফরেনসিক আবিষ্কার (Key Forensic Findings)
1. **কন্টেইনারের ধরন**: এটি একটি Advanced Installer SFX (Self-Extracting Executable) কন্টেইনার।
2. **পেলোড অবফাসকেশন (Stream Inversion - Method 2)**: কন্টেইনারে লুকানো 7z আর্কাইভ ফাইলের প্রথম **৫১২টি বাইট (`0x200`)** বিটওয়াইজ ইনভার্ট (`^ 0xFF`) করা হয়েছিল (Ghidra ফাংশন `FUN_0053aa50`-এ উদঘাটিত)। এর ফলে সাধারণ অ্যান্টিভাইরাস বা 7-Zip/WinRAR টুল ফাইলটিকে বৈধ আর্কাইভ হিসেবে শনাক্ত করতে পারে না এবং ডিকম্প্রেস করতে গেলে `Data Error` দেয়।
3. **`Decoder.dll`-এর ভূমিকা**: SFX স্টাবটি রান করার সময় এটি `%TEMP%` ফোল্ডারে `decoder.dll` ড্রপ করে মেমরিতে লোড করে। এরপর এর এক্সপোর্টেড ফাংশন ব্যবহার করে লুকানো 7z আর্কাইভটি ডিস্কে আনপ্যাক করে।
4. **শনাক্তকৃত পেলোডসমূহ**:
   - `326FA02\FILES.7z`: এর ভেতর সন্দেহজনক এক্সিকিউটেবল ও স্ক্রিপ্ট রয়েছে (`fidelity.exe`, `NSudo.exe`, `WindowsService.exe`, `Run.vbs`)।
   - `326FA02\OceanofGames-Top-Games-EXE.7z`: ইনস্টলারের মূল সেটআপ MSI।
   - `Step 3 - Setup_Install_Game.ini`: ইনস্টলেশনের কনফিগারেশন ও প্রোডাক্ট GUID।

> [!WARNING]
> মূল ইনস্টলার ফাইলটি সরাসরি চালু করলে ক্ষতিকারক ফাইলগুলো উচ্চ প্রিভিলেজসহ কম্পিউটারে রান হতে পারে। **কখনোই মূল ইনস্টলারটি সরাসরি চালাবেন না।** পরিবর্তে, এখানে তৈরি করা নিরাপদ এক্সট্রাক্টর টুলটি ব্যবহার করে কোনো কোড এক্সিকিউট না করেই পেলোডগুলো নিরাপদে খতিয়ে দেখুন।

---

## ২. বাইনারি রিভার্স ইঞ্জিনিয়ারিং (`Decoder.dll`)

Ghidra MCP সার্ভারের মাধ্যমে ডিসঅ্যাসেম্বলি ও ডিকম্পাইলেশন করে দেখা গেছে যে, `Decoder.dll` হলো একটি ৩২-বিট x86 PE ডাইনামিক লিঙ্ক লাইব্রেরি (Image Base: `0x10000000`, আকার: ২০৯,৯২০ বাইট)। এটি মূলত 7-Zip ইঞ্জিনের (`NArchive::N7z`) একটি স্ট্যাটিক্যালি লিঙ্কড লাইব্রেরি।

### ২.১ এক্সপোর্টেড ফাংশনসমূহ (Exported ABI Functions)

ডিএলএল (DLL) ফাইলটি `__cdecl` কলিং কনভেনশন ব্যবহার করে নিচের ৪টি ফাংশন এক্সপোর্ট করে:

| ক্রমিক | ফাংশনের নাম | প্রোটোটাইপ | কাজের বিবরণ |
| :---: | :--- | :--- | :--- |
| **১** | `EndExtraction` | `void __cdecl EndExtraction(DecoderContext *ctx)` | আর্কাইভ বন্ধ করে, স্ট্রিম রিলিজ করে, মেমরি ও অবজেক্ট মুক্ত করে। |
| **২** | `ExtractAllFiles` | `int __cdecl ExtractAllFiles(DecoderContext *ctx)` | আর্কাইভের সব ফাইল রিকার্সিভলি নির্ধারিত ডিরেক্টরিতে এক্সট্র্যাক্ট করে। সফল হলে `0` রিটার্ন করে। |
| **৩** | `GetTotalFilesSize` | `UINT64 __cdecl GetTotalFilesSize(DecoderContext *ctx)` | আর্কাইভের মেটাডাটা স্ক্যান করে সব আনকম্প্রেসড ফাইলের মোট আকার (বাইটে) রিটার্ন করে। |
| **৪** | `InitExtraction` | `int __cdecl InitExtraction(DecoderContext *ctx)` | কন্টেইনার ফাইল হ্যান্ডেল ওপেন করে, অফসেট স্ক্যান করে ডিকম্প্রেশন সেশন শুরু করে। সফল হলে `0` রিটার্ন করে। |

### ২.২ `DecoderContext` স্ট্রাকচার মেমরি লেআউট

কলিং প্রোগ্রামটি মেমরিতে কমপক্ষে `0x260` বাইটের একটি বাফার তৈরি করে নিম্নোক্ত স্ট্রাকচার আকারে `InitExtraction`-এ পাঠায়:

```c
#pragma pack(push, 1)
typedef struct DecoderContext {
    HANDLE       hFile;              // [0x00] কন্টেইনার ফাইলের হ্যান্ডেল (GENERIC_READ)
    UINT64       archiveOffset;      // [0x08] ফাইলে 7z আর্কাইভের শুরু হওয়ার বাইট অফসেট
    UINT64       archiveSize;        // [0x10] আর্কাইভের মোট আকার (বাইটে)
    WCHAR        outputDir[260];     // [0x18] ফাইল সংরক্ষণের আউটপুট পাথ (Unicode UTF-16)
    WCHAR       *pOutputDir;         // [0x220] outputDir বাফারের পয়েন্টার
    void        *pInternalState;     // [0x224] ডিএলএল-এর ইন্টারনাল স্টেট পয়েন্টার
    void        *pProgressCallback;  // [0x228] প্রগ্রেস বার কলব্যাক ফাংশন পয়েন্টার
    void        *pProgressContext;   // [0x22C] প্রগ্রেস কলব্যাক ইউজার ডাটা
    void        *pFilterObject;      // [0x230] স্ট্রিম ফিল্টার/ডিক্রিপশন অবজেক্ট পয়েন্টার
    BYTE         reserved[0x2C];     // [0x234] বাফারের আকার >= 0x260 করার জন্য প্যাডিং
} DecoderContext;
#pragma pack(pop)
```

---

## ৩. Advanced Installer SFX কন্টেইনার বিন্যাস

ইনস্টলার ফাইলের একেবারে শেষ প্রান্তে একটি SFX ট্রেলার (Trailer) থাকে। এই ট্রেলারটি রিভার্স ইঞ্জিনিয়ারিং করে কোনো কোড না চালিয়েই ভেতরে লুকানো সব ফাইল উদ্ধার করা সম্ভব হয়েছে:

```
[ PE Executable Header & Code (মূল এক্সিকিউটেবল) ]
[ পেলোড ১: decoder.dll (সাধারণ ফাইল) ]
[ পেলোড ২: 326FA02\FILES.7z (অবফাসকেটেড 7z ফাইল) ]
[ পেলোড ৩: 326FA02\OceanofGames-Top-Games-EXE.7z (অবফাসকেটেড 7z ফাইল) ]
[ পেলোড ৪: Step 3 - Setup_Install_Game.ini (কনফিগারেশন) ]
[ ফাইল টেবিল: এন্ট্রি হেডার ও ফাইলের নাম ]
[ SFX ট্রেলার স্ট্রাকচার: "ADVINSTSFX" সিগনেচার দিয়ে শেষ হয় ]
```

### ট্রেলার স্ট্রাকচার (`SFXTrailer`):
```c
#pragma pack(push, 1)
typedef struct {
    DWORD table_end_offset;       // ফাইল টেবিলের সমাপ্তি অফসেট
    DWORD num_files;              // মোট লুকানো ফাইলের সংখ্যা
    DWORD flags;                  // ফ্ল্যাগ
    DWORD table_end_offset2;      // টেবিল সমাপ্তির মিরর অফসেট
    DWORD table_start_offset;     // ফাইল টেবিলের সূচনা অফসেট
    DWORD archive_start_offset;   // প্রথম পেলোডের সূচনা অফসেট
    char  hash[32];               // ইন্টিগ্রিটি হ্যাশ
    DWORD trailer_size;           // ট্রেলারের আকার
    char  signature[10];          // সিগনেচার: "ADVINSTSFX" (১০ বাইট)
} SFXTrailer;
#pragma pack(pop)
```

### হেডার ও স্ট্রিম অবফাসকেশন সমাধান (Method 2 De-obfuscation):
যেসব ফাইলের মেথড `2`, সেগুলোর প্রথম **৫১২টি বাইট (`0x200`)**-কে বিটওয়াইজ ইনভার্ট (`^ 0xFF`) করে মূল 7z হেডার ও LZMA2 স্ট্রিম পুনরুদ্ধার করা হয় (Ghidra `FUN_0053aa50` বিশ্লেষণ অনুযায়ী):
```
আসল 7z সিগনেচার:  37 7A BC AF 27 1C 00 04 ...
অবফাসকেটেড বাইট:   C8 85 43 50 D8 E3 FF FB ...
পুনরুদ্ধার সূত্র:   buffer[i] ^= 0xFF (i < 512 বা 0x200 এর জন্য)
```

---

## ৪. নতুন কোড আর্কিটেকচার ও রি-ইমপ্লিমেন্টেশন

[`src/lib/decoder.cpp`](file:///F:/Project/skill/decoder/src/lib/decoder.cpp)-এ সম্পূর্ণ নতুনভাবে তৈরি কোডটির বৈশিষ্ট্য:
1. **COM স্ট্রিম র‍্যাপার (`CInFileStream`)**: উইন্ডোজের `HANDLE` নিয়ে নির্দিষ্ট অফসেটের মাঝে ফাইল রিড করে। অবফাসকেটেড স্ট্রিম পেলে প্রথম ৫১২ বাইট স্বয়ংক্রিয়ভাবে ইনভার্ট করে মেমরিতে সঠিক হেডারে রূপান্তর করে।
2. **ডিকম্প্রেশন ইঞ্জিন (`IInArchive`)**: 7-Zip COM ইন্টারফেসের মাধ্যমে আর্কাইভের ডাটা ডিকম্প্রেস করে।
3. **ডিরেক্টরি তৈরি (`CExtractCallback`)**: ফাইল লেখার আগে স্বয়ংক্রিয়ভাবে ফোল্ডার তৈরি করে পাথ এরর রোধ করে।
4. **এক্সপোর্ট সামঞ্জস্য (`decoder.def`)**: আসল ডিএলএল-এর মতো হুবহু একই নামে এক্সপোর্ট প্রদান করে।

---

## ৫. বিল্ড এবং ব্যবহারের নির্দেশিকা

### প্রজেক্ট বিল্ড করা
প্রজেক্টের রুট থেকে সরাসরি বিল্ড স্ক্রিপ্টটি চালান:
```cmd
F:\Project\skill\decoder\scripts\build.bat
```

এটি স্বয়ংক্রিয়ভাবে Visual Studio কম্পাইলার ব্যবহার করে [`bin/`](file:///F:/Project/skill/decoder/bin) ফোল্ডারে নিম্নোক্ত ফাইলগুলো তৈরি করবে:
* `bin\x86\decoder.dll`: আসল ৩২-বিট ডিএলএল-এর হুবহু ড্রপ-ইন বিকল্প।
* `bin\x64\decoder.dll`: ৬৪-বিট ডিএলএল।
* `bin\x64\standalone_extractor.exe`: নিরাপদ স্ট্যান্ডঅ্যালন সি এক্সট্রাকশন টুল।
* `bin\x64\gof_extractor.exe`: GOF কন্টেইনার এক্সট্রাকশন টুল।
* `bin\x64\test_decoder.exe`: টেস্ট হারনেস।

### নিরাপদ এক্সট্রাকশন টুলস ব্যবহার (ম্যালওয়্যার রান না করে)

১. **পাইথন প্যাকেজ ইনস্টল ও গ্লোবাল কমান্ড (`safe-extractor`):**
```cmd
pip install -e .
# সরাসরি টার্মিনাল থেকে চালান:
safe-extractor "Data_xe.bin" -o "Clean_Game"
safe-extractor "Step 3 - Setup_Install_Game.exe" -o "Extracted_Payloads"
```

২. **স্ট্যান্ডঅ্যালন সি টুল (`standalone_extractor.exe`):**
```cmd
F:\Project\skill\decoder\bin\x64\standalone_extractor.exe -o "F:\Project\skill\decoder\samples\extracted_clean" "ইনস্টলারের_পাথ.exe"
```

### ডিএলএল এক্সপোর্ট টেস্ট
```cmd
F:\Project\skill\decoder\bin\x64\test_decoder.exe -d F:\Project\skill\decoder\bin\x64\decoder.dll
```
সফল হলে নিচের ৪টি এক্সপোর্ট প্রদর্শিত হবে:
```
[+] All 4 ABI exports successfully resolved!
    -> InitExtraction:    0x00007FFDC38C1A60
    -> GetTotalFilesSize: 0x00007FFDC38C1A40
    -> ExtractAllFiles:   0x00007FFDC38C18E0
    -> EndExtraction:     0x00007FFDC38C1850
```

---

## ৬. স্বয়ংক্রিয় গিটহাব অ্যাকশন (GitHub Actions CI/CD)

এই প্রজেক্টে একটি আধুনিক অটোমেশন পাইপলাইন যুক্ত করা হয়েছে (`.github/workflows/build-and-release.yml`):
* **অটোমেটিক বাইনারি কম্পাইলেশন**: প্রতিবার কোড পুশ হলে GitHub সার্ভারে x64 এবং x86 (Win32) উভয় আর্কিটেকচারের ডিএলএল এবং এক্সিকিউটেবল স্বয়ংক্রিয়ভাবে কম্পাইল ও টেস্ট হয়।
* **পাইথন প্যাকেজ ও হুইল তৈরি**: পাইথন প্যাকেজ (`.whl` এবং `.tar.gz`) স্বয়ংক্রিয়ভাবে বিল্ড হয়।
* **অটো রিলিজ পাবলিশিং**: যখনই কোনো ভার্সন ট্যাগ (যেমন: `v1.0.0`) পুশ করা হয়, GitHub Action স্বয়ংক্রিয়ভাবে নতুন রিলিজ তৈরি করে সব বাইনারি জিপ এবং প্যাকেজ অ্যাটাচ করে দেয়।
