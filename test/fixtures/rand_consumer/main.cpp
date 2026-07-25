#include <array>
#include <cstdint>

#include "cdf/modules/rand/rand.h"

int main()
{
    std::array<uint8_t, 16> randomBytes{};
    return cdf::GetRand(randomBytes.data(), randomBytes.size()) ==
                   cdf::CcsecCryptErrorCode::CCSEC_CRYPT_OK
               ? 0
               : 1;
}
