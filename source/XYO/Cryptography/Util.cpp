// Cryptography
// Copyright (c) 2016-2026 Grigore Stefan <g_stefan@yahoo.com>
// MIT License (MIT) <http://opensource.org/licenses/MIT>
// SPDX-FileCopyrightText: 2016-2026 Grigore Stefan <g_stefan@yahoo.com>
// SPDX-License-Identifier: MIT

#include <XYO/Cryptography/Util.hpp>
#include <XYO/Cryptography/SHA256.hpp>
#include <XYO/Cryptography/SHA512.hpp>

namespace XYO::Cryptography::Util {

	template <typename THash>
	static bool fileHash(const char *fileName, String &hash) {
		File fileIn;
		if (!fileIn.openRead(fileName)) {
			return false;
		};
		// read returns a short count both at end of file and on a read error,
		// File does not tell which one, so compare the bytes hashed with the file size
		if (!fileIn.seekFromEnd(0)) {
			return false;
		};
		uint64_t fileSize = fileIn.seekTell();
		if (fileSize == (uint64_t)-1) {
			return false;
		};
		if (!fileIn.seekFromBegin(0)) {
			return false;
		};
		size_t readLn;
		uint64_t totalLn = 0;
		THash hashFile;
		hashFile.processInit();
		uint8_t buffer[32768];
		for (;;) {
			readLn = fileIn.read(buffer, sizeof(buffer));
			if (readLn > 0) {
				hashFile.processU8(buffer, readLn);
				totalLn += readLn;
			};
			if (readLn < sizeof(buffer)) {
				break;
			};
		};
		fileIn.close();
		if (totalLn != fileSize) {
			return false;
		};
		hashFile.processDone();
		hash = hashFile.getHashHex();
		return true;
	};

	bool fileHashSHA256(const char *fileName, String &hash) {
		return fileHash<SHA256>(fileName, hash);
	};

	bool fileHashSHA512(const char *fileName, String &hash) {
		return fileHash<SHA512>(fileName, hash);
	};

};
