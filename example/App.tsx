import React from "react";
import { StyleSheet, Text, View } from "react-native";
import * as ExpoScrypt from "../src";

export default function App() {
  const testScrypt = async () => {
    try {
      const result = await ExpoScrypt.scrypt("password", "salt", {
        N: 16384, // CPU/memory cost parameter
        r: 8, // Block size parameter
        p: 1, // Parallelization parameter
        dkLen: 32, // Desired key length in bytes
      });
      console.log("Scrypt result:", result);
    } catch (error) {
      console.error("Scrypt error:", error);
    }
  };

  testScrypt();

  return (
    <View style={styles.container}>
      <Text>Open up App.tsx to start working with expo-scrypt!</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: "#fff",
    alignItems: "center",
    justifyContent: "center",
  },
});
