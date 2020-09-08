/* eslint-disable no-bitwise */
import React, { useCallback } from 'react';
import {
  StyleSheet,
  Text,
  View,
  SafeAreaView,
  ScrollView,
  Button,
  ActivityIndicator,
} from 'react-native';

import base64 from 'base64-js';
import Sodium from 'react-native-sodium';

const TestResult: React.FC<{ value: boolean | undefined; name: string }> = (
  props
) => {
  const text = props.value === undefined ? '?' : props.value ? 'Pass' : 'Fail';
  const style = {
    color: props.value === undefined ? 'black' : props.value ? 'green' : 'red',
  };
  return (
    <View style={styles.testContainer}>
      <Text style={styles.testLabel}>{props.name}:</Text>
      <Text style={[styles.testResult, style]}>{text}</Text>
    </View>
  );
};

const TestValue: React.FC<{ value: string | undefined; name: string }> = (
  props
) => {
  return (
    <View style={styles.testContainer}>
      <Text style={styles.testLabel}>{props.name}:</Text>
      <Text style={[styles.testResult]}>{props.value}</Text>
    </View>
  );
};

const App: React.FC = () => {
  const [sodium_version_string, setSodiumVersion] = React.useState<string>();
  const [sodiumError, setSodiumError] = React.useState<string>();
  const [randombytes_uniform, setRandomBytesUniform] = React.useState<
    boolean
  >();
  const [randombytes_buf, setRandomBytesBuf] = React.useState<boolean>();
  const [randombytes_random, setRandomBytesRandom] = React.useState<boolean>();
  const [crypto_secretbox1, setCryptoSecretBox1] = React.useState<boolean>();
  const [crypto_auth, setCryptoAuth] = React.useState<boolean>();
  const [crypto_auth_verify, setCryptoAuthVerify] = React.useState<boolean>();
  const [crypto_box1, setCryptoBox1] = React.useState<boolean>();
  const [crypto_box2, setCryptoBox2] = React.useState<boolean>();
  const [base64Encryption, setBase64Encryption] = React.useState<boolean>();
  const [hex, setHex] = React.useState<boolean>();
  const [crypto_aead_xchacha20poly1305_ietf, setCryptoXchacha] = React.useState<
    boolean
  >();

  const _handleError = (error: string) => {
    console.log(error);
    setSodiumError(error);
  };

  const _testRandom1 = () => {
    setRandomBytesUniform(undefined);
    let freq: Array<number> = [];
    let p = [];
    for (let i = 0; i < 256; ++i) freq[i] = 0;
    for (let i = 0; i < 20 * 256; ++i)
      p.push(Sodium.randombytes_uniform(256).then((v) => ++freq[v]));
    Promise.all(p).then(() => {
      var fail = false;
      for (let i = 0; i < 256 && !fail; ++i) if (!freq[i]) fail = true;
      setRandomBytesUniform(!fail);
    });
  };

  const _testRandom2 = () => {
    setRandomBytesBuf(undefined);
    let freq: Array<number> = [];
    for (let i = 0; i < 256; ++i) freq[i] = 0;
    Sodium.randombytes_buf(20 * 256).then((value) => {
      let a = base64.toByteArray(value);
      for (let i = 0; i < a.length; ++i) ++freq[a[i]];
      let fail = false;
      for (let i = 0; i < 256 && !fail; ++i) if (!freq[i]) fail = true;
      setRandomBytesBuf(!fail);
    });
  };

  const _testRandom3 = () => {
    setRandomBytesRandom(undefined);
    let freq: Array<number> = [];
    let p = [];
    for (let i = 0; i < 256; ++i) freq[i] = 0;
    for (let i = 0; i < 5 * 256; ++i)
      p.push(
        Sodium.randombytes_random().then((v) => {
          ++freq[v & 0xff];
          ++freq[(v >>> 8) & 0xff];
          ++freq[(v >>> 16) & 0xff];
          ++freq[(v >>> 24) & 0xff];
        })
      );
    Promise.all(p).then(() => {
      var fail = false;
      for (let i = 0; i < 256 && !fail; ++i) if (!freq[i]) fail = true;
      setRandomBytesRandom(!fail);
    });
  };

  const _testSecretBox1 = () => {
    const k = base64.fromByteArray(
      new Uint8Array([
        0x1b,
        0x27,
        0x55,
        0x64,
        0x73,
        0xe9,
        0x85,
        0xd4,
        0x62,
        0xcd,
        0x51,
        0x19,
        0x7a,
        0x9a,
        0x46,
        0xc7,
        0x60,
        0x09,
        0x54,
        0x9e,
        0xac,
        0x64,
        0x74,
        0xf2,
        0x06,
        0xc4,
        0xee,
        0x08,
        0x44,
        0xf6,
        0x83,
        0x89,
      ])
    );

    const n = base64.fromByteArray(
      new Uint8Array([
        0x69,
        0x69,
        0x6e,
        0xe9,
        0x55,
        0xb6,
        0x2b,
        0x73,
        0xcd,
        0x62,
        0xbd,
        0xa8,
        0x75,
        0xfc,
        0x73,
        0xd6,
        0x82,
        0x19,
        0xe0,
        0x03,
        0x6b,
        0x7a,
        0x0b,
        0x37,
      ])
    );

    const m = base64.fromByteArray(
      new Uint8Array([
        0xbe,
        0x07,
        0x5f,
        0xc5,
        0x3c,
        0x81,
        0xf2,
        0xd5,
        0xcf,
        0x14,
        0x13,
        0x16,
        0xeb,
        0xeb,
        0x0c,
        0x7b,
        0x52,
        0x28,
        0xc5,
        0x2a,
        0x4c,
        0x62,
        0xcb,
        0xd4,
        0x4b,
        0x66,
        0x84,
        0x9b,
        0x64,
        0x24,
        0x4f,
        0xfc,
        0xe5,
        0xec,
        0xba,
        0xaf,
        0x33,
        0xbd,
        0x75,
        0x1a,
        0x1a,
        0xc7,
        0x28,
        0xd4,
        0x5e,
        0x6c,
        0x61,
        0x29,
        0x6c,
        0xdc,
        0x3c,
        0x01,
        0x23,
        0x35,
        0x61,
        0xf4,
        0x1d,
        0xb6,
        0x6c,
        0xce,
        0x31,
        0x4a,
        0xdb,
        0x31,
        0x0e,
        0x3b,
        0xe8,
        0x25,
        0x0c,
        0x46,
        0xf0,
        0x6d,
        0xce,
        0xea,
        0x3a,
        0x7f,
        0xa1,
        0x34,
        0x80,
        0x57,
        0xe2,
        0xf6,
        0x55,
        0x6a,
        0xd6,
        0xb1,
        0x31,
        0x8a,
        0x02,
        0x4a,
        0x83,
        0x8f,
        0x21,
        0xaf,
        0x1f,
        0xde,
        0x04,
        0x89,
        0x77,
        0xeb,
        0x48,
        0xf5,
        0x9f,
        0xfd,
        0x49,
        0x24,
        0xca,
        0x1c,
        0x60,
        0x90,
        0x2e,
        0x52,
        0xf0,
        0xa0,
        0x89,
        0xbc,
        0x76,
        0x89,
        0x70,
        0x40,
        0xe0,
        0x82,
        0xf9,
        0x37,
        0x76,
        0x38,
        0x48,
        0x64,
        0x5e,
        0x07,
        0x05,
      ])
    );

    const handleError = (e: any) => {
      setCryptoSecretBox1(false);
      console.log(e);
    };
    setCryptoSecretBox1(undefined);

    Sodium.crypto_secretbox_easy(m, n, k)
      .then((c) => Sodium.crypto_secretbox_open_easy(c, n, k), handleError)
      .then((mm) => {
        setCryptoSecretBox1(m === mm);
      }, handleError);
  };

  const _testAuth1 = useCallback(() => {
    const k = base64.fromByteArray(
      // prettier-ignore
      new Uint8Array([
        // Jefe
        0x4a,0x65,0x66,0x65, 0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      ])
    );

    const c = base64.fromByteArray(
      // prettier-ignore
      new Uint8Array([
        // what do ya want for nothing?
        0x77,0x68,0x61,0x74,0x20,0x64,0x6f,0x20,0x79,0x61,0x20,0x77,0x61,0x6e,0x74,0x20,0x66,0x6f,0x72,0x20,0x6e,0x6f,0x74,0x68,0x69,0x6e,0x67,0x3f,
      ])
    );

    const a = base64.fromByteArray(
      new Uint8Array([
        0x16,
        0x4b,
        0x7a,
        0x7b,
        0xfc,
        0xf8,
        0x19,
        0xe2,
        0xe3,
        0x95,
        0xfb,
        0xe7,
        0x3b,
        0x56,
        0xe0,
        0xa3,
        0x87,
        0xbd,
        0x64,
        0x22,
        0x2e,
        0x83,
        0x1f,
        0xd6,
        0x10,
        0x27,
        0x0c,
        0xd7,
        0xea,
        0x25,
        0x05,
        0x54,
      ])
    );

    setCryptoAuth(undefined);
    setCryptoAuthVerify(undefined);

    Sodium.crypto_auth(c, k)
      .then((aa) => {
        setCryptoAuth(a === aa);
        Sodium.crypto_auth_verify(a, c, k)
          .then((r) => {
            setCryptoAuthVerify(r === 0);
          })
          .catch((error) => {
            setCryptoAuthVerify(false);
            _handleError(error);
          });
      })
      .catch((error) => {
        setCryptoAuthVerify(false);
        _handleError(error);
      });
  }, []);

  const _testBox1 = () => {
    setCryptoBox1(undefined);
    const mlen_max = 1000;

    Promise.all([
      Sodium.crypto_box_keypair(),
      Sodium.crypto_box_keypair(),
    ]).then(([alice, bob]) => {
      let p = [];
      for (let mlen = 0; mlen <= mlen_max; mlen++) {
        p.push(
          Promise.all([
            Sodium.randombytes_buf(Sodium.crypto_box_NONCEBYTES),
            Sodium.randombytes_buf(mlen),
          ]).then(([n, m]) =>
            Sodium.crypto_box_easy(m, n, bob.pk, alice.sk)
              .then((c) => Sodium.crypto_box_open_easy(c, n, alice.pk, bob.sk))
              .then((mm) => mm === m)
          )
        );
      }
      Promise.all(p).then((pr) => {
        let fail = false;
        for (let i = 0; i < pr.length && !fail; ++i) if (!pr[i]) fail = true;
        setCryptoBox1(!fail);
      });
    });
  };

  const _testBox2 = () => {
    setCryptoBox2(undefined);
    const alicepk = base64.fromByteArray(
      new Uint8Array([
        0x85,
        0x20,
        0xf0,
        0x09,
        0x89,
        0x30,
        0xa7,
        0x54,
        0x74,
        0x8b,
        0x7d,
        0xdc,
        0xb4,
        0x3e,
        0xf7,
        0x5a,
        0x0d,
        0xbf,
        0x3a,
        0x0d,
        0x26,
        0x38,
        0x1a,
        0xf4,
        0xeb,
        0xa4,
        0xa9,
        0x8e,
        0xaa,
        0x9b,
        0x4e,
        0x6a,
      ])
    );

    const alicesk = base64.fromByteArray(
      new Uint8Array([
        0x77,
        0x07,
        0x6d,
        0x0a,
        0x73,
        0x18,
        0xa5,
        0x7d,
        0x3c,
        0x16,
        0xc1,
        0x72,
        0x51,
        0xb2,
        0x66,
        0x45,
        0xdf,
        0x4c,
        0x2f,
        0x87,
        0xeb,
        0xc0,
        0x99,
        0x2a,
        0xb1,
        0x77,
        0xfb,
        0xa5,
        0x1d,
        0xb9,
        0x2c,
        0x2a,
      ])
    );

    const bobpk = base64.fromByteArray(
      new Uint8Array([
        0xde,
        0x9e,
        0xdb,
        0x7d,
        0x7b,
        0x7d,
        0xc1,
        0xb4,
        0xd3,
        0x5b,
        0x61,
        0xc2,
        0xec,
        0xe4,
        0x35,
        0x37,
        0x3f,
        0x83,
        0x43,
        0xc8,
        0x5b,
        0x78,
        0x67,
        0x4d,
        0xad,
        0xfc,
        0x7e,
        0x14,
        0x6f,
        0x88,
        0x2b,
        0x4f,
      ])
    );

    const bobsk = base64.fromByteArray(
      new Uint8Array([
        0x5d,
        0xab,
        0x08,
        0x7e,
        0x62,
        0x4a,
        0x8a,
        0x4b,
        0x79,
        0xe1,
        0x7f,
        0x8b,
        0x83,
        0x80,
        0x0e,
        0xe6,
        0x6f,
        0x3b,
        0xb1,
        0x29,
        0x26,
        0x18,
        0xb6,
        0xfd,
        0x1c,
        0x2f,
        0x8b,
        0x27,
        0xff,
        0x88,
        0xe0,
        0xeb,
      ])
    );

    const nonce = base64.fromByteArray(
      new Uint8Array([
        0x69,
        0x69,
        0x6e,
        0xe9,
        0x55,
        0xb6,
        0x2b,
        0x73,
        0xcd,
        0x62,
        0xbd,
        0xa8,
        0x75,
        0xfc,
        0x73,
        0xd6,
        0x82,
        0x19,
        0xe0,
        0x03,
        0x6b,
        0x7a,
        0x0b,
        0x37,
      ])
    );

    const m = base64.fromByteArray(
      new Uint8Array([
        0xbe,
        0x07,
        0x5f,
        0xc5,
        0x3c,
        0x81,
        0xf2,
        0xd5,
        0xcf,
        0x14,
        0x13,
        0x16,
        0xeb,
        0xeb,
        0x0c,
        0x7b,
        0x52,
        0x28,
        0xc5,
        0x2a,
        0x4c,
        0x62,
        0xcb,
        0xd4,
        0x4b,
        0x66,
        0x84,
        0x9b,
        0x64,
        0x24,
        0x4f,
        0xfc,
        0xe5,
        0xec,
        0xba,
        0xaf,
        0x33,
        0xbd,
        0x75,
        0x1a,
        0x1a,
        0xc7,
        0x28,
        0xd4,
        0x5e,
        0x6c,
        0x61,
        0x29,
        0x6c,
        0xdc,
        0x3c,
        0x01,
        0x23,
        0x35,
        0x61,
        0xf4,
        0x1d,
        0xb6,
        0x6c,
        0xce,
        0x31,
        0x4a,
        0xdb,
        0x31,
        0x0e,
        0x3b,
        0xe8,
        0x25,
        0x0c,
        0x46,
        0xf0,
        0x6d,
        0xce,
        0xea,
        0x3a,
        0x7f,
        0xa1,
        0x34,
        0x80,
        0x57,
        0xe2,
        0xf6,
        0x55,
        0x6a,
        0xd6,
        0xb1,
        0x31,
        0x8a,
        0x02,
        0x4a,
        0x83,
        0x8f,
        0x21,
        0xaf,
        0x1f,
        0xde,
        0x04,
        0x89,
        0x77,
        0xeb,
        0x48,
        0xf5,
        0x9f,
        0xfd,
        0x49,
        0x24,
        0xca,
        0x1c,
        0x60,
        0x90,
        0x2e,
        0x52,
        0xf0,
        0xa0,
        0x89,
        0xbc,
        0x76,
        0x89,
        0x70,
        0x40,
        0xe0,
        0x82,
        0xf9,
        0x37,
        0x76,
        0x38,
        0x48,
        0x64,
        0x5e,
        0x07,
        0x05,
      ])
    );

    const c = base64.fromByteArray(
      new Uint8Array([
        0xf3,
        0xff,
        0xc7,
        0x70,
        0x3f,
        0x94,
        0x00,
        0xe5,
        0x2a,
        0x7d,
        0xfb,
        0x4b,
        0x3d,
        0x33,
        0x05,
        0xd9,
        0x8e,
        0x99,
        0x3b,
        0x9f,
        0x48,
        0x68,
        0x12,
        0x73,
        0xc2,
        0x96,
        0x50,
        0xba,
        0x32,
        0xfc,
        0x76,
        0xce,
        0x48,
        0x33,
        0x2e,
        0xa7,
        0x16,
        0x4d,
        0x96,
        0xa4,
        0x47,
        0x6f,
        0xb8,
        0xc5,
        0x31,
        0xa1,
        0x18,
        0x6a,
        0xc0,
        0xdf,
        0xc1,
        0x7c,
        0x98,
        0xdc,
        0xe8,
        0x7b,
        0x4d,
        0xa7,
        0xf0,
        0x11,
        0xec,
        0x48,
        0xc9,
        0x72,
        0x71,
        0xd2,
        0xc2,
        0x0f,
        0x9b,
        0x92,
        0x8f,
        0xe2,
        0x27,
        0x0d,
        0x6f,
        0xb8,
        0x63,
        0xd5,
        0x17,
        0x38,
        0xb4,
        0x8e,
        0xee,
        0xe3,
        0x14,
        0xa7,
        0xcc,
        0x8a,
        0xb9,
        0x32,
        0x16,
        0x45,
        0x48,
        0xe5,
        0x26,
        0xae,
        0x90,
        0x22,
        0x43,
        0x68,
        0x51,
        0x7a,
        0xcf,
        0xea,
        0xbd,
        0x6b,
        0xb3,
        0x73,
        0x2b,
        0xc0,
        0xe9,
        0xda,
        0x99,
        0x83,
        0x2b,
        0x61,
        0xca,
        0x01,
        0xb6,
        0xde,
        0x56,
        0x24,
        0x4a,
        0x9e,
        0x88,
        0xd5,
        0xf9,
        0xb3,
        0x79,
        0x73,
        0xf6,
        0x22,
        0xa4,
        0x3d,
        0x14,
        0xa6,
        0x59,
        0x9b,
        0x1f,
        0x65,
        0x4c,
        0xb4,
        0x5a,
        0x74,
        0xe3,
        0x55,
        0xa5,
      ])
    );

    Sodium.crypto_box_easy(m, nonce, bobpk, alicesk).then((cc) => {
      Sodium.crypto_box_open_easy(cc, nonce, alicepk, bobsk).then((mm) => {
        setCryptoBox2(c === cc && m === mm);
      });
    });
  };

  const _testXchachaEncryption = async () => {
    setCryptoXchacha(undefined);
    const message = 'Test message fdsfsdfsdgdfgxdvxbfd';
    const key = await Sodium.crypto_aead_xchacha20poly1305_ietf_keygen();
    const nonce = await Sodium.randombytes_buf(
      Sodium.crypto_aead_xchacha20poly1305_IETF_NPUBBYTES
    );
    const encrypted = await Sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      message,
      nonce,
      key,
      null
    );

    const decrypted = await Sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      encrypted,
      nonce,
      key,
      null
    );
    setCryptoXchacha(decrypted === message);
  };

  const testBase64 = async () => {
    setBase64Encryption(undefined);
    const message = 'Hello world';
    const encrypted = await Sodium.to_base64(
      message,
      Sodium.base64_variant_ORIGINAL
    );
    const decrypted = await Sodium.from_base64(
      encrypted,
      Sodium.base64_variant_ORIGINAL
    );
    setBase64Encryption(decrypted === message);
  };

  const testHex = async () => {
    setHex(undefined);
    const message = 'THello world';
    const encrypted = await Sodium.to_hex(message);
    const decrypted = await Sodium.from_hex(encrypted);
    setHex(decrypted === message);
  };

  const startTests = useCallback(() => {
    Sodium.sodium_version_string()
      .then((version) => setSodiumVersion(version))
      .catch((error) => _handleError(error));

    // Random data generation
    // _testRandom1();
    // _testRandom2();
    // _testRandom3();

    // // Secret key cryptography - authenticated encryption
    // _testSecretBox1();

    // // Secret key cryptography - authentication
    // _testAuth1();

    // // Public-key cryptography - authenticated encryption
    // _testBox1();
    // _testBox2();
    testBase64();
    testHex();
    _testXchachaEncryption();
  }, []);

  const isFinished =
    !sodiumError &&
    sodium_version_string &&
    randombytes_random &&
    randombytes_uniform &&
    randombytes_buf &&
    crypto_secretbox1 &&
    crypto_auth &&
    crypto_auth_verify &&
    crypto_box1 &&
    crypto_box2;

  return (
    <SafeAreaView style={styles.container}>
      <ScrollView>
        <Button title="Start tests" onPress={startTests} />
        <TestValue name="sodium_version_string" value={sodium_version_string} />
        <TestResult name="randombytes_random" value={randombytes_random} />
        <TestResult name="randombytes_uniform" value={randombytes_uniform} />
        <TestResult name="randombytes_buf" value={randombytes_buf} />
        <TestResult name="crypto_secretbox1" value={crypto_secretbox1} />
        <TestResult name="crypto_auth" value={crypto_auth} />
        <TestResult name="crypto_auth_verify" value={crypto_auth_verify} />
        <TestResult name="crypto_box1" value={crypto_box1} />
        <TestResult name="crypto_box2" value={crypto_box2} />
        <TestResult name="base64" value={base64Encryption} />
        <TestResult name="hex" value={hex} />
        <TestResult
          name="crypto_aead_xchacha20poly1305_ietf"
          value={crypto_aead_xchacha20poly1305_ietf}
        />
        <ActivityIndicator animating={!isFinished} />
      </ScrollView>
    </SafeAreaView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#F5FCFF',
    padding: 5,
  },

  testContainer: {
    flex: 1,
    flexDirection: 'row',
    padding: 5,
  },

  testLabel: {
    flex: 4,
    textAlign: 'left',
    color: '#333333',
  },

  testResult: {
    flex: 1,
    textAlign: 'center',
  },
  instructions: {
    textAlign: 'left',
    color: '#333333',
    marginBottom: 5,
  },
});

export default App;
