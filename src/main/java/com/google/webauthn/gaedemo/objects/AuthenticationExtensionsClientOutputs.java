package com.google.webauthn.gaedemo.objects;

import com.google.common.io.BaseEncoding;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

public class AuthenticationExtensionsClientOutputs {

  CableRegistrationData cableData;

  public AuthenticationExtensionsClientOutputs() {
    cableData = null;
  }

  public void parseExtensions(JsonElement json) {
    JsonObject extensionsObject = json.getAsJsonObject();
    if (extensionsObject.has("cableRegistration")) {
      JsonElement cableObject = extensionsObject.get("cableRegistration");
      byte[] cborObject = BaseEncoding.base64().decode(cableObject.getAsString());
      cableData = CableRegistrationData.parseFromCbor(cborObject);
    }
  }

  public CableRegistrationData getCableData() {
    return cableData;
  }

}
