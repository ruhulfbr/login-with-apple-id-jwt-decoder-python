# requirements
# pyjwt
# requests
import json
import requests
import jwt.algorithms


class AppleJwtTokenDecoder:
    APPLE_PUBLIC_KEY_URL = 'https://appleid.apple.com/auth/keys'
    JWKS = None

    def get_jwt_header(self, token):
        header = jwt.get_unverified_header(token)
        kid = header['kid']
        alg = header['alg']
        return kid, alg

    def get_apple_jwks(self) -> list:
        if self.JWKS is None:
            res = requests.get(self.APPLE_PUBLIC_KEY_URL).json()
            return res['keys']
        else:
            return self.JWKS['keys']

    def find_jwk_from_apple_jwks(self, kid, alg, patch=False):
        if patch:
            self.JWKS = None

        for key in self.get_apple_jwks():
            if key['kid'] == kid and key['alg'] == alg:
                return key

     #audience = Client ID
    def decode_jwt(self, token, audience):
        kid, alg = self.get_jwt_header(token)
        jwk = self.find_jwk_from_apple_jwks(kid, alg)
        if jwk is None:
            jwk = self.find_jwk_from_apple_jwks(kid, alg, patch=True)
        algorithm = jwt.algorithms.get_default_algorithms()[alg]
        public_key = algorithm.from_jwk(
            json.dumps(jwk)
        )
        # payload descriptions
        # https://sarunw.com/posts/sign-in-with-apple-3/#what-to-validate
        payload = jwt.decode(
            token,
            public_key,
            algorithms=alg,
            verify=True,
            audience=audience,
        )
        return payload
