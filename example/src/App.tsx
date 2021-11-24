import * as React from 'react';

import { StyleSheet, View, Text, NativeModules } from 'react-native';
import base64 from 'base64-js';

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

export default function App() {
  const [randombytes_buf, setRandomBytesBuf] = React.useState<boolean>();
  const [randombytes_random, setRandomBytesRandom] = React.useState<boolean>();

  // const testRandom2 = () => {
  //   setRandomBytesBuf(undefined);
  //   let freq: Array<number> = [];
  //   for (let i = 0; i < 256; ++i) freq[i] = 0;
  //   const value = global.randombytes_buf(20 * 256);
  //   let a = base64.toByteArray(value);
  //   for (let i = 0; i < a.length; ++i) ++freq[a[i]];
  //   let fail = false;
  //   for (let i = 0; i < 256 && !fail; ++i)
  //     if (!freq[i]) {
  //       console.log(a, i);
  //       fail = true;
  //     }
  //   setRandomBytesBuf(!fail);
  // };

  React.useEffect(() => {
    const message = 'Test message fdsfsdfsdgdfgxdvxbfd';
    const key = global.crypto_aead_xchacha20poly1305_ietf_keygen();
    const nonce = global.randombytes_buf(
      NativeModules.Sodium.crypto_aead_xchacha20poly1305_IETF_NPUBBYTES
    );
    const encrypted = global.crypto_aead_xchacha20poly1305_ietf_encrypt(
      message,
      nonce,
      key,
      null
    );

    const decrypted = global.crypto_aead_xchacha20poly1305_ietf_decrypt(
      encrypted,
      nonce,
      key,
      null
    );
    console.log(decrypted);
    // console.log(NativeModules.Sodium);
    // setResult(global && global.randombytes_random());
    // testRandom2();
    // testRandom3();
  }, []);

  return (
    <View style={styles.container}>
      <TestResult name="randombytes_random" value={randombytes_random} />
      <TestResult name="randombytes_buf" value={randombytes_buf} />
    </View>
  );
}

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
