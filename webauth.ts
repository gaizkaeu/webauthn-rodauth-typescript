const unpack = function (v: string) {
  return Uint8Array.from(atob(v.replace(/-/g, "+").replace(/_/g, "/")), (c) =>
    c.charCodeAt(0)
  );
};

const pack = function (v: ArrayBuffer) {
  return btoa(String.fromCharCode.apply(null, [...new Uint8Array(v)]))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
};

export type AuthValue = {
  type: string;
  id: string;
  rawId: string;
  response: {
    authenticatorData: string;
    clientDataJSON: string;
    signature: string;
    userHandle?: string;
  };
};

export type RegisterValue = {
  type: string;
  id: string;
  rawId: string;
  response: {
    attestationObject: string;
    clientDataJSON: string;
  };
};

type RegisterOptionsBinary = {
  challenge: ArrayBuffer;
  rp: {
    name: string;
    host: string;
  };
  user: {
    id: ArrayBuffer;
    name: string;
    displayName: string;
  };
  pubKeyCredParams: {
    type: "public-key";
    alg: number;
  }[];
  authenticatorSelection: {
    authenticatorAttachment: "platform" | "cross-platform";
    requireResidentKey: boolean;
    userVerification: UserVerificationRequirement;
  };
  excludeCredentials: {
    id: ArrayBuffer;
    type: "public-key";
  }[];
  timeout: number;
  attestation: AttestationConveyancePreference;
  extensions: any;
};

export type RegisterOptions = {
  challenge: string;
  rp: {
    name: string;
    host: string;
  };
  user: {
    id: string;
    name: string;
    displayName: string;
  };
  pubKeyCredParams: {
    type: "public-key";
    alg: number;
  }[];
  authenticatorSelection: {
    authenticatorAttachment: "platform" | "cross-platform";
    requireResidentKey: boolean;
    userVerification: UserVerificationRequirement;
  };
  excludeCredentials: {
    id: string;
    type: "public-key";
  }[];
  timeout: number;
  attestation: AttestationConveyancePreference;
  extensions: any;
};

type AuthOptions = {
  challenge: string;
  allowCredentials: {
    id: string;
    type: "public-key";
  }[];
  rpId: string;
  timeout: number;
  userVerification: UserVerificationRequirement;
  extensions: any;
};

type AuthOptionsBinary = {
  challenge: ArrayBuffer;
  allowCredentials: {
    id: ArrayBuffer;
    type: "public-key";
  }[];
  rpId: string;
  timeout: number;
  userVerification: UserVerificationRequirement;
  extensions: any;
};

export const register = async function (
  opts: RegisterOptions
): Promise<RegisterValue> {
  if (navigator.credentials) {
    const formattedOpts: RegisterOptionsBinary = {
      ...opts,
      excludeCredentials: [],
      challenge: unpack(opts.challenge),
      user: {
        ...opts.user,
        id: unpack(opts.user.id),
      },
    };
    formattedOpts.challenge = unpack(opts.challenge);

    opts.excludeCredentials.forEach(function (cred) {
      formattedOpts.excludeCredentials.push({
        id: unpack(cred.id),
        type: cred.type,
      });
    });

    //console.log(opts);
    const cred_ = await navigator.credentials.create({
      publicKey: formattedOpts,
    });
    //console.log(cred);
    //window.cred = cred
    if (!cred_) {
      throw new Error("Could not create credential");
    }
    const cred = cred_ as PublicKeyCredential;
    const response = cred.response as AuthenticatorAttestationResponse;

    const rawId = pack(cred.rawId);
    const registerValue = {
      type: cred.type,
      id: rawId,
      rawId: rawId,
      response: {
        attestationObject: pack(response.attestationObject),
        clientDataJSON: pack(response.clientDataJSON),
      },
    } as RegisterValue;

    return registerValue;
  } else {
    throw new Error("WebAuthn not supported");
  }
};

export const authenticate = async function (
  opts: AuthOptions
): Promise<AuthValue> {
  if (navigator.credentials) {
    const formattedOpts: AuthOptionsBinary = {
      ...opts,
      allowCredentials: [],
      challenge: new ArrayBuffer(0),
    };
    formattedOpts.challenge = unpack(opts.challenge);

    opts.allowCredentials.forEach(function (cred) {
      formattedOpts.allowCredentials.push({
        id: unpack(cred.id),
        type: cred.type,
      });
    });

    //console.log(opts);
    const cred_ = await navigator.credentials.get({ publicKey: formattedOpts });
    //console.log(cred);
    //window.cred = cred
    if (!cred_) {
      throw new Error("Could not create credential");
    }
    const cred = cred_ as unknown as PublicKeyCredential;
    const response = cred.response as AuthenticatorAssertionResponse;

    const rawId = pack(cred.rawId);
    const authValue = {
      type: cred.type,
      id: rawId,
      rawId: rawId,
      response: {
        authenticatorData: pack(response.authenticatorData),
        clientDataJSON: pack(response.clientDataJSON),
        signature: pack(response.signature),
      },
    } as AuthValue;

    if (response.userHandle) {
      authValue.response.userHandle = pack(response.userHandle);
    }
    return authValue;
  } else {
    throw new Error("Not supported navigator");
  }
};
