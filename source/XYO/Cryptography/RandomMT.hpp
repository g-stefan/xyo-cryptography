// Cryptography
// Copyright (c) 2022 Grigore Stefan <g_stefan@yahoo.com>
// MIT License (MIT) <http://opensource.org/licenses/MIT>
// SPDX-FileCopyrightText: 2022 Grigore Stefan <g_stefan@yahoo.com>
// SPDX-License-Identifier: MIT

#ifndef XYO_CRYPTOGRAPHY_RANDOMMT_HPP
#define XYO_CRYPTOGRAPHY_RANDOMMT_HPP

#ifndef XYO_CRYPTOGRAPHY_DEPENDENCY_HPP
#	include <XYO/Cryptography/Dependency.hpp>
#endif

namespace XYO::Cryptography {

	class RandomMT : public Object {
			XYO_DISALLOW_COPY_ASSIGN_MOVE(RandomMT);

		protected:
			int index;
			uint32_t mt[624];
			uint32_t value;

		public:
			XYO_CRYPTOGRAPHY_EXPORT RandomMT();
			XYO_CRYPTOGRAPHY_EXPORT void seed(uint32_t);
			XYO_CRYPTOGRAPHY_EXPORT uint32_t nextRandom();
			XYO_CRYPTOGRAPHY_EXPORT uint32_t getValue();
			XYO_CRYPTOGRAPHY_EXPORT void copy(RandomMT &value);
	};

};

#endif
