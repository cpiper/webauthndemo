/*
 * Copyright 2018 Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 *
 */

package com.google.webauthn.gaedemo.crypto;

import com.google.common.io.BaseEncoding;
import com.google.common.primitives.Bytes;
import com.google.webauthn.gaedemo.exceptions.WebAuthnException;
import com.google.webauthn.gaedemo.objects.CablePairingData;
import com.google.webauthn.gaedemo.objects.CableSessionData;

import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.util.Random;

public class CableTest {
  
  public static KeyPair generateKeyPair() {
    try {
      ECGenParameterSpec spec = new ECGenParameterSpec("secp256r1");
      KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
      gen.initialize(spec);
      KeyPair keyPair = gen.generateKeyPair();
      return keyPair;
    } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
      throw new RuntimeException(e);
    }
  }
  
  public static byte[] encodeUncompressedECPublicKey(ECPublicKey publicKey) {
    ECPoint point = publicKey.getW();
    byte[] x = point.getAffineX().toByteArray();
    byte[] y = point.getAffineY().toByteArray();

    byte[] output = new byte[65];
    // The order of arraycopy() is important, because the coordinates may have a one-byte leading 0
    // for the sign bit of two's complement form
    System.arraycopy(y, y.length - 32, output, output.length - 32, 32);
    System.arraycopy(x, x.length - 32, output, 1, 32);
    output[0] = 4;
    ECKeyPairGenerator keyGen = new ECKeyPairGenerator();
    return output;
  }

  @Test
  public void decodePublic() throws Exception {
    KeyPair keyPair = Crypto.generateKeyPair();
    
    byte[] xy = Crypto.compressECPublicKey((ECPublicKey) keyPair.getPublic());
    
    X9ECParameters curve = SECNamedCurves.getByName("secp256r1");
    org.bouncycastle.math.ec.ECPoint point;
    try {
      byte[] encodedPublicKey = xy;
      point = curve.getCurve().decodePoint(encodedPublicKey);
    } catch (RuntimeException e) {
      throw new WebAuthnException("Couldn't parse user public key", e);
    }

  }

  @Test
  public void testGenerateSessionData_vectors() {
    Cable cable = new Cable(new Random() {
      private static final long serialVersionUID = -7092153420386472236L;

      @Override
      public void nextBytes(byte[] bytes) {
        for (int i = 0; i < bytes.length; ++i) {
          bytes[i] = (byte) 0xAA;
        }
      }
    });

    CablePairingData pairingData = new CablePairingData(1,
        Hex.decode("202122232425262728292A2B2C2D2E2F202122232425262728292A2B2C2D2E2F"),
        Hex.decode("101112131415161718191A1B1C1D1E1F101112131415161718191A1B1C1D1E1F"));

    CableSessionData actual = cable.generateSessionData(pairingData);

    CableSessionData expected =
        new CableSessionData(1, Hex.decode("AAAAAAAAAAAAAAAAC50F4E92238F1BE7"),
            Hex.decode("75B83487AE3DB1C1159C00EB992C984D"),
            Hex.decode("073B97D8D142EA3A04B16BD3DC81553334577A20F398DBBC02FBD18B9354BAD2"));
    Assert.assertEquals(expected, actual);
  }
}
