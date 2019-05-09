package com.google.webauthn.gaedemo.objects;

import java.util.ArrayList;
import java.util.List;

import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.UnicodeString;
import co.nstant.in.cbor.model.UnsignedInteger;

public class CableRegistrationData {
  List<Integer> versions;
  Integer maxVersion;
  byte[] publicKey;

  public CableRegistrationData() {}

  public static CableRegistrationData parseFromCbor(byte[] cborCableData) {
    CableRegistrationData cableData = new CableRegistrationData();

    Map cborMap = null;
    List<DataItem> cborItems;
    try {
      cborItems = CborDecoder.decode(cborCableData);
      cborMap = (Map) cborItems.get(0);
    } catch (CborException e) {
      return cableData;
    }

    for (DataItem data : cborMap.getKeys()) {
      if (data instanceof UnicodeString) {
        if (((UnicodeString) data).getString().equals("version")) {
          cableData.versions = new ArrayList<>();
          cableData.versions.add(((UnsignedInteger) cborMap.get(data)).getValue().intValue());
        } else if (((UnicodeString) data).getString().equals("maxVersion")) {
          cableData.maxVersion = ((UnsignedInteger) cborMap.get(data)).getValue().intValue();
        } else if (((UnicodeString) data).getString().equals("authenticatorPublicKey")) {
          cableData.publicKey = ((ByteString) data).getBytes();
        }
      }
    }

    return cableData;
  }
}
