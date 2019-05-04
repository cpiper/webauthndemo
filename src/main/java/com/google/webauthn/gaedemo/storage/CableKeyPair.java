// Copyright 2019 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package com.google.webauthn.gaedemo.storage;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Date;

import com.google.appengine.api.datastore.Entity;
import com.google.appengine.api.datastore.Key;
import com.google.appengine.api.datastore.KeyFactory;
import com.google.common.io.BaseEncoding;
import com.google.webauthn.gaedemo.server.Datastore;

public class CableKeyPair {
  public static final String KIND = "CableKeyPair";
  public static final String KEY_PAIR_PROPERTY = "keypair";
  public static final String TIMESTAMP_PROPERTY = "created";
  private Date created;
  private KeyPair keyPair;
  private long id;

  public CableKeyPair(KeyPair keyPair) {
    this.keyPair = keyPair;
    this.created = new Date();
  }

  public long save(String currentUser) throws IOException {
    Key parentKey = KeyFactory.createKey(User.KIND, currentUser);

    Entity session = new Entity(KIND, parentKey);

    // Serialize the KeyPair
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    ObjectOutputStream out = new ObjectOutputStream(baos);
    out.writeObject(keyPair);
    
    session.setProperty(KEY_PAIR_PROPERTY, BaseEncoding.base64().encode(baos.toByteArray()));
    session.setProperty(TIMESTAMP_PROPERTY, new Date());

    Key stored = Datastore.getDatastore().put(session);
    this.id = stored.getId();
    return id;
  }
}
