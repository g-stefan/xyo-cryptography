// Cryptography
// Copyright (c) 2016-2023 Grigore Stefan <g_stefan@yahoo.com>
// MIT License (MIT) <http://opensource.org/licenses/MIT>
// SPDX-FileCopyrightText: 2016-2023 Grigore Stefan <g_stefan@yahoo.com>
// SPDX-License-Identifier: MIT

#include <XYO/Cryptography/Crypt.hpp>
#include <XYO/Cryptography/XOR8.hpp>
#include <XYO/Cryptography/SHA512.hpp>

namespace XYO::Cryptography::Crypt {

	//
	//  [PSEUDO RANDOM SEED SHA512][SIGNATURE SHA512][LENGTH 64BIT - XOR - SHA512 CTR MODE][DATA - XOR - (SHA512 CTR MODE)*2]
	//

	void encrypt(const uint8_t *password, size_t passwordSize, const uint8_t *data, size_t dataSize, Buffer &output) {
		//
		size_t dataLn = ((dataSize / 64) + 1) * 64;
		output.setSize(64 + 64 + 8 + dataLn);
		//
		SHA512 randomSalt;
		randomSalt.processInit();
		randomSalt.processU8(password, passwordSize);
		randomSalt.processU8(data, dataSize);
		UConvert::u64ToU8(DateTime::timestampInMilliseconds(), output.buffer);
		randomSalt.processU8(output.buffer, 8);
		randomSalt.processDone();
		randomSalt.toU8(output.buffer);
		//
		SHA512 keyBase;
		keyBase.processInit();
		keyBase.processU8(output.buffer, 64);
		keyBase.processU8(password, passwordSize);
		keyBase.processDone();
		keyBase.toU8(&output.buffer[64]);
		//
		SHA512 key;
		SHA512 keyActive;
		uint8_t counterBuffer[8];
		uint8_t xorBuffer[64];
		key.processInit();
		key.processU8(output.buffer, 128);
		keyActive.copy(key);
		UConvert::u64ToU8(0, counterBuffer);
		keyActive.processU8(counterBuffer, 8);
		keyActive.processDone();
		keyActive.toU8(xorBuffer);
		UConvert::u64ToU8(dataSize, &output.buffer[64 + 64]);
		xor8(&output.buffer[64 + 64], 8, xorBuffer, 8);
		//
		size_t k;
		size_t dataLnX = 0;
		size_t dataToProcess = dataSize;
		size_t counter;
		for (k = 0, counter = 1; k < dataLn; k += 64, dataToProcess -= 64, counter += 2) {

			if (dataToProcess > 64) {
				dataLnX = 64;
			} else {
				dataLnX = dataToProcess;
			};

			UConvert::u64ToU8(counter, counterBuffer);
			keyActive.copy(key);
			keyActive.processU8(counterBuffer, 8);
			keyActive.processDone();
			keyActive.toU8(xorBuffer);
			xor8(xorBuffer, 64, &data[k], dataLnX);
			memcpy(&output.buffer[64 + 64 + 8 + k], xorBuffer, 64);

			UConvert::u64ToU8(counter + 1, counterBuffer);
			keyActive.copy(key);
			keyActive.processU8(counterBuffer, 8);
			keyActive.processDone();
			keyActive.toU8(xorBuffer);
			xor8(&output.buffer[64 + 64 + 8 + k], 64, xorBuffer, 64);
		};
		//

		//
		SHA512 checkHash;
		checkHash.processInit();
		checkHash.processU8(output.buffer, output.size);
		checkHash.processDone();
		checkHash.toU8(&output.buffer[64]);
		output.length = output.size;
	};

	bool decrypt(const uint8_t *password, size_t passwordSize, const uint8_t *data, size_t dataSize_, Buffer &output) {
		//
		if (dataSize_ < 64 + 64 + 8) {
			return false;
		};
		//
		SHA512 keyBase;
		keyBase.processInit();
		keyBase.processU8(data, 64);
		keyBase.processU8(password, passwordSize);
		keyBase.processDone();
		//
		SHA512 key;
		SHA512 keyActive;
		uint8_t counterBuffer[8];
		uint8_t xorBuffer[64];
		key.processInit();
		key.processU8(data, 64);
		keyBase.toU8(xorBuffer);
		key.processU8(xorBuffer, 64);
		keyActive.copy(key);
		UConvert::u64ToU8(0, counterBuffer);
		keyActive.processU8(counterBuffer, 8);
		keyActive.processDone();
		keyActive.toU8(xorBuffer);
		memcpy(counterBuffer, &data[64 + 64], 8);
		xor8(counterBuffer, 8, xorBuffer, 8);
		//
		size_t dataSize = (size_t)UConvert::u64FromU8(counterBuffer);
		size_t dataLn = ((dataSize / 64) + 1) * 64;
		//
		if (64 + 64 + 8 + dataLn > dataSize_) {
			return false;
		};
		//
		SHA512 checkHash;
		checkHash.processInit();
		checkHash.processU8(data, 64);
		keyBase.toU8(xorBuffer);
		checkHash.processU8(xorBuffer, 64);
		checkHash.processU8(&data[64 + 64], 8);
		checkHash.processU8(&data[64 + 64 + 8], dataLn);
		checkHash.processDone();
		checkHash.toU8(xorBuffer);
		//
		if (memcmp(xorBuffer, &data[64], 64) != 0) {
			return false;
		};
		//
		//
		output.setSize(dataSize);
		//
		key.processInit();
		key.processU8(data, 64);
		keyBase.toU8(xorBuffer);
		key.processU8(xorBuffer, 64);
		//
		size_t k;
		size_t dataLnX = 0;
		size_t dataToProcess = dataSize;
		size_t counter;
		for (k = 0, counter = 1; k < dataLn; k += 64, dataToProcess -= 64, counter += 2) {

			if (dataToProcess > 64) {
				dataLnX = 64;
			} else {
				dataLnX = dataToProcess;
			};

			UConvert::u64ToU8(counter, counterBuffer);
			keyActive.copy(key);
			keyActive.processU8(counterBuffer, 8);
			keyActive.processDone();
			keyActive.toU8(xorBuffer);
			xor8(xorBuffer, 64, &data[64 + 64 + 8 + k], dataLnX);
			memcpy(&output.buffer[k], xorBuffer, dataLnX);

			UConvert::u64ToU8(counter + 1, counterBuffer);
			keyActive.copy(key);
			keyActive.processU8(counterBuffer, 8);
			keyActive.processDone();
			keyActive.toU8(xorBuffer);
			xor8(xorBuffer, 64, &output.buffer[k], dataLnX);
			memcpy(&output.buffer[k], xorBuffer, dataLnX);
		};
		//
		output.length = output.size;
		return true;
	};

	bool encryptFile(const uint8_t *password, size_t passwordSize, const char *fileNameIn, const char *fileNameOut) {
		Buffer fileContents;
		if (Shell::fileGetContents(fileNameIn, fileContents)) {
			Buffer output;
			encrypt(password, passwordSize, fileContents.buffer, fileContents.length, output);
			return Shell::filePutContents(fileNameOut, output);
		};
		return false;
	};

	bool decryptFile(const uint8_t *password, size_t passwordSize, const char *fileNameIn, const char *fileNameOut) {
		Buffer fileContents;
		if (Shell::fileGetContents(fileNameIn, fileContents)) {
			Buffer output;
			if (decrypt(password, passwordSize, fileContents.buffer, fileContents.length, output)) {
				return Shell::filePutContents(fileNameOut, output);
			};
		};
		return false;
	};

	bool checkIntegrity(const uint8_t *password, size_t passwordSize, const uint8_t *data, size_t dataSize_, const uint8_t *integrity) {
		//
		if (dataSize_ < 64 + 64 + 8) {
			return false;
		};
		//
		SHA512 keyBase;
		keyBase.processInit();
		keyBase.processU8(data, 64);
		keyBase.processU8(password, passwordSize);
		keyBase.processDone();
		//
		SHA512 key;
		SHA512 keyActive;
		uint8_t counterBuffer[8];
		uint8_t xorBuffer[64];
		key.processInit();
		key.processU8(data, 64);
		keyBase.toU8(xorBuffer);
		key.processU8(xorBuffer, 64);
		keyActive.copy(key);
		UConvert::u64ToU8(0, counterBuffer);
		keyActive.processU8(counterBuffer, 8);
		keyActive.processDone();
		keyActive.toU8(xorBuffer);
		memcpy(counterBuffer, &data[64 + 64], 8);
		xor8(counterBuffer, 8, xorBuffer, 8);
		//
		size_t dataSize = (size_t)UConvert::u64FromU8(counterBuffer);
		size_t dataLn = ((dataSize / 64) + 1) * 64;
		//
		if (64 + 64 + 8 + dataLn > dataSize_) {
			return false;
		};
		//
		SHA512 checkHash;
		checkHash.processInit();
		checkHash.processU8(data, 64);
		keyBase.toU8(xorBuffer);
		checkHash.processU8(xorBuffer, 64);
		checkHash.processU8(&data[64 + 64], 8);
		checkHash.processU8(&data[64 + 64 + 8], dataLn);
		checkHash.processDone();
		checkHash.toU8(xorBuffer);
		//
		if (memcmp(xorBuffer, &data[64], 64) == 0) {
			if (memcmp(integrity, &data[64], 64) == 0) {
				return true;
			};
		};
		//
		return false;
	};

};
