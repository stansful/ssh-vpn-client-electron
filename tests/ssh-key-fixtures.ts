/**
 * Throwaway keys made with OpenSSH 10.3 ssh-keygen for the tests, so the SSH
 * core is checked against real files rather than its own idea of the format.
 * Every encrypted one uses the passphrase below. `publicKey` is the matching
 * .pub line without its comment.
 */
export const FIXTURE_PASSPHRASE = "correct horse";

export interface SshKeyFixture {
  /** How the key was made. */
  made: string;
  privateKey: string;
  publicKey: string;
}

export const SSH_KEY_FIXTURES = {
  ed25519: {
    made: "ssh-keygen -t ed25519 (defaults: aes256-ctr, bcrypt, 24 rounds)",
    privateKey: [
      "-----BEGIN OPENSSH PRIVATE KEY-----",
      "b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABCMjoXTIq",
      "5KFfvpkyzr/8pHAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIICnEGHs7nq2sw+8",
      "0Q1Z9lrbyRIbnWSRVZR7PqxbERaHAAAAoBuuHwMC/Ln5Ta2EPnLPaTP98e8TH4Wsu56Xdf",
      "aMKWkFVRISgiAc9Tpcj4ut3OlUA2v4TTu5AY072nGia2Qa/uN2YdmVGh9JesCUlN8Ekcdw",
      "EpgSxOFZtegvOJtS/IUaC4RcQFS/7tkXKma/iM8Mv1BNqTNP0ajDIGvmBnYsp1PeYEroYc",
      "3yUEwUCthqRPfyc2dji7sjIv6dR0VGxyxjK+c=",
      "-----END OPENSSH PRIVATE KEY-----"
    ].join("\n"),
    publicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIICnEGHs7nq2sw+80Q1Z9lrbyRIbnWSRVZR7PqxbERaH"
  },
  rsa: {
    made: "ssh-keygen -t rsa -b 2048 -a 2",
    privateKey: [
      "-----BEGIN OPENSSH PRIVATE KEY-----",
      "b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABD4xKpHOy",
      "HoAOV+3PTVhnzMAAAAAgAAAAEAAAEXAAAAB3NzaC1yc2EAAAADAQABAAABAQDXiZsML6Eg",
      "a15UGK5lmvd2qWP/qJOtH+r/VMLKvJ+OcKHB/H7q9+YNgb3AlK2QslCwKPw2q8EdQr/7eB",
      "i3CzuOTBh1sEP1YqbFVOxSRhA6lTP9M1dpyY37cuswcyjfhN4dnYbQwlHkGaFt6zk0510i",
      "ylEXhYxqOpfKTzbaeEbB5jcD/eG8MT4lvHW7Zz7c8HiqO1+bajgL2rP/9T/9oGCJNfN+kK",
      "jz5TqnCRIgTb70BHZ5G2dQhhOgrP1TPk2hWMLR4iz23vxXXVvCwYFUxV+EmODWqQrlOfVr",
      "m9ImP7BZ1c3tIfTQHNWOMZcmXEiGqymFzXAETlDOCL7cVAVmTOtTAAAD0BIh3c0bG2h1DO",
      "+0P9GHWuJLgOm9hF1BxW+n9Hhpqn2OnI8NQXBfWXgGs5gSKJWkgDaqaK49jQyaArFT8gdp",
      "UPdPGbO7UqTJcqe+c06E/VijLedWbnuc3Rwl5mhGuXc88jo49M2Ma+/TG++ZytbsruGl1j",
      "djm+mmsFIwUzh0uPBoM8q7oJlVEGnMkG9oGnEKYTF9bJLrPA629mPZ5fUmfcwAcdugqFqI",
      "sq5I/41Ky43dukiDF1I4zIfMphDV1FZ0Yme10gtSpBqO60ef511daI7lu2LyKjSASCygd/",
      "xpnK7IWfIgXFGAdKUoBpy2n1b9Vy3gq3rJqCntKt3WTYA377RsT6bLj6C5pWRLTUAoKx9o",
      "E2W0QClA0UysuKg8F+7Qx1VvY6Bkwu5FcYnAgFF8xGsSiDZu752jPJAvngwfDKGmkbALHU",
      "SFmnk4L/ANlavuMsl20Jd65hSFhzP1PFOhvucujiRJNUcyu/X1NLsu2dPB3tNz3OOk1K7e",
      "8u95F+uFgzX0TTjZPMW5q3DHgnmPhGk3pcJ+1rcdxW/AAVME3TWbwsaiyjUFJhIOjkFBA6",
      "hlKssbg9qfZ9vvtaSNjt6miPeVKPWA4Ny0P7IL8R61ts2pg0xQOxEk6pSOJi40PMeSWWCa",
      "IPHCBT3dICuqP0iWXmLjWY7+WLTfwszlX76em9SwySc0TZpCMFSWo5MFIyYgrC+DQ+CPKy",
      "Wq+F/UpoNWQHBIsAjQg8Csf351dvujH3AZ0ivuBZU5EULKDuigigd2SOYtkiduHuvO0JGC",
      "4u5AqkaKSw7yK446GvoK1GAPOncxAM7BXNWCpYBRocYYhdoMcAFawY++Jlgf08A/L8etT9",
      "/6lKhd57ZMqo916CX9be3eIdLZG0enR/YwuNxI3/agT1mIY4DcVbBgTOzYkYWzZafJw/Bg",
      "TqykW6v4VbpeAv31qRmuR0jogtj4ndalaufzh1yh0UYgn2TlxDMXhT1JNi/KQBIvLVlpV3",
      "E3ZuHgywfbnZSwoiqqerFrlZPrkZRqn2rY+HLuvT3YSI37oIFcZUo0+LgSGdI/M+DM/BiY",
      "Mov1H6pQD1QrWoUvplm0me1xNBI9VoAv4Ip3LrHcQlJZi5LdvHodjDui727HQma2GLvRRW",
      "RWDnxSw0187eykJxlb/IL+Nt/3TiCrrUgmFkgI7TUMtBtYoKCprhKwHDJKr948YM3DS1lq",
      "Y4Xdg8oEyVdUdBCdZxXX87PI0KEY9qxpU5VGvDWnHQNXBbclf7kSTGDVw4F+md8l9CeUCC",
      "ZtnOgdl8bKG0IjwSkdc/US/pYEMFg=",
      "-----END OPENSSH PRIVATE KEY-----"
    ].join("\n"),
    publicKey: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDXiZsML6Ega15UGK5lmvd2qWP/qJOtH+r/VMLKvJ+OcKHB/H7q9+YNgb3AlK2QslCwKPw2q8EdQr/7eBi3CzuOTBh1sEP1YqbFVOxSRhA6lTP9M1dpyY37cuswcyjfhN4dnYbQwlHkGaFt6zk0510iylEXhYxqOpfKTzbaeEbB5jcD/eG8MT4lvHW7Zz7c8HiqO1+bajgL2rP/9T/9oGCJNfN+kKjz5TqnCRIgTb70BHZ5G2dQhhOgrP1TPk2hWMLR4iz23vxXXVvCwYFUxV+EmODWqQrlOfVrm9ImP7BZ1c3tIfTQHNWOMZcmXEiGqymFzXAETlDOCL7cVAVmTOtT"
  },
  ecdsaP256: {
    made: "ssh-keygen -t ecdsa -b 256 -a 2",
    privateKey: [
      "-----BEGIN OPENSSH PRIVATE KEY-----",
      "b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABCchAlM3a",
      "cKzmZwH/zmHiDMAAAAAgAAAAEAAABoAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlz",
      "dHAyNTYAAABBBNyZJ7Ec2zuu0/Pj3Kn8tsOHgvQvXX4TC15QiCbhVqUUxcYrGoqKmHhhVl",
      "aEv3m/fDkCRh8Rm3Kh7BjPtDLS7g0AAACwcljX/sK6jXR2HX0G3h345v5dqOR61lLkGYoL",
      "FAMt8J5Yfanrct2XR87hYwkBL1GxPX25D9uY+fvwHF1CsQLCQQlU2WYu+lL4al8iRhMAMi",
      "DQO22vzEqgM2L4ZflHgA6VyAVtM1++vYN9C9bETezc4/PuJMwhO8Hk6hx5YeR17+g0kYdi",
      "TINGF6ROb+drnBrhN6677weV+GG9pE21kJNOV8Y+7aaHnHNvvwxx3TYWt8Y=",
      "-----END OPENSSH PRIVATE KEY-----"
    ].join("\n"),
    publicKey: "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNyZJ7Ec2zuu0/Pj3Kn8tsOHgvQvXX4TC15QiCbhVqUUxcYrGoqKmHhhVlaEv3m/fDkCRh8Rm3Kh7BjPtDLS7g0="
  },
  ecdsaP384: {
    made: "ssh-keygen -t ecdsa -b 384 -a 2",
    privateKey: [
      "-----BEGIN OPENSSH PRIVATE KEY-----",
      "b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABC2jn84op",
      "Vt8wPIW7UaYs3/AAAAAgAAAAEAAACIAAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlz",
      "dHAzODQAAABhBJhDBQPkLVRnkO2AVXR0pZhltibDmiODyg5bnW0vEsfjTdFzHVIeYMCo7O",
      "Y/u5rRxyujgKoyLOzmqAUM2htXM0bDPW/3Ke2keDiAnB7TXQ5tsWuc6EdJzPT/jnGlNHad",
      "lAAAAOBKs9aGsMI9NwdUQR+6XOBNYauvJ4IncKRz9+qdk7MUQ1hPrL4d+nOtvfGlCqMz8O",
      "yc5Pp0FflzaqSNiHpX1kOXiISAqFvUiqhgNvh7y87ES2IqebPhlC29ZV5OANCdK3988ak2",
      "xKchLXjoAJR4Tj+qhto0erb/3kEgnuHa7VjcMLI8H1DmuP5ybdiv5dM+xFbq3Bci0vXclL",
      "f+aFE8byBHj2siJenn5NAPkGexAnlfw1S9tGYLAYqzrMDz22ot+du0B7nVV9S0UXsLaVdW",
      "d+BTpUiYxavKv0556URjStXQUA==",
      "-----END OPENSSH PRIVATE KEY-----"
    ].join("\n"),
    publicKey: "ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBJhDBQPkLVRnkO2AVXR0pZhltibDmiODyg5bnW0vEsfjTdFzHVIeYMCo7OY/u5rRxyujgKoyLOzmqAUM2htXM0bDPW/3Ke2keDiAnB7TXQ5tsWuc6EdJzPT/jnGlNHadlA=="
  },
  ecdsaP521: {
    made: "ssh-keygen -t ecdsa -b 521 -a 2",
    privateKey: [
      "-----BEGIN OPENSSH PRIVATE KEY-----",
      "b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABCpoEZBU8",
      "CnbNAicGSu1M7AAAAAAgAAAAEAAACsAAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlz",
      "dHA1MjEAAACFBAAzPqqkWPGdziyik7IcMlPbxKQUThvlcOZi1s30raL8fo+s3s+tOSVmES",
      "uW4AqsxFU3U3TnRrs5KwNBBry6dPCSZQDKGjYzWiJXQ5lHhhBn3mvYRIW1lNskJWke39fB",
      "VvvLYFkO+8DLcxwUB46KxIQ/3Q6U6hUu8Un28nQ+XVYkkV9P8wAAARC+KrfkvFDIZPhpgJ",
      "aPE2QUWmgbHJ3Zw3M+M9GKcLyuf54IrneCJ0Von/WNIxW59TRg1MDaKfmdnHev6B0U7FK1",
      "iGUQv/nXeYnBLY7vmwWGpFAtyti6X/1IyHTFelM5mNiOlJXGLfcVGiXoVtHcaVdGXJ2F/O",
      "PaLTA/D/H5UdtVqBD1SJk3vuoApI48eWg5LeBA8oKZ2SJL4yiiQfDWbhR8z9f9YuIjT5B5",
      "QH2yLWSDhISoW9QC89eToM/2ajyhQpG6tjlDaIKfPjcd5+DkLPIX0S1RuxOv86txGBduGa",
      "k0bAGWDdEIoN1j2DbaSzBz8A/jZDv52vs0b+Kc5CIfWVRS//00LaXcbnQm08MReAlILQ==",
      "-----END OPENSSH PRIVATE KEY-----"
    ].join("\n"),
    publicKey: "ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAAzPqqkWPGdziyik7IcMlPbxKQUThvlcOZi1s30raL8fo+s3s+tOSVmESuW4AqsxFU3U3TnRrs5KwNBBry6dPCSZQDKGjYzWiJXQ5lHhhBn3mvYRIW1lNskJWke39fBVvvLYFkO+8DLcxwUB46KxIQ/3Q6U6hUu8Un28nQ+XVYkkV9P8w=="
  },
  ed25519Aes128Ctr: {
    made: "ssh-keygen -t ed25519 -a 2 -Z aes128-ctr",
    privateKey: [
      "-----BEGIN OPENSSH PRIVATE KEY-----",
      "b3BlbnNzaC1rZXktdjEAAAAACmFlczEyOC1jdHIAAAAGYmNyeXB0AAAAGAAAABC/axSkYy",
      "QyQkW/j5sYgicGAAAAAgAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIPjS9RAConW5JCWI",
      "Na9YOi4yh5co3K4ahFCG7QGZ3b37AAAAoKi8DUD5hu8jUURUpwaKRLxr50bIffYUFwP6oA",
      "/XvsY1AQbRHUKc8jiew4n7884Mf8sl3Wnmu6SIAJGqo6BFCHTwDnuJgJ4LFfXL/G/DaKg4",
      "hStpRfpCnQWqoDsbTRsckb+yTwCatU5BN1NRmNSq9qRni7m7bA0BWK/24ETAgB/ORA4+oN",
      "00QKe5MCcxIDhrC0+/O3Hb/PZwScdLo8bdanE=",
      "-----END OPENSSH PRIVATE KEY-----"
    ].join("\n"),
    publicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPjS9RAConW5JCWINa9YOi4yh5co3K4ahFCG7QGZ3b37"
  },
  ed25519Aes256Cbc: {
    made: "ssh-keygen -t ed25519 -a 2 -Z aes256-cbc",
    privateKey: [
      "-----BEGIN OPENSSH PRIVATE KEY-----",
      "b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jYmMAAAAGYmNyeXB0AAAAGAAAABCwbS9nRj",
      "TKQeuSmNeeP3RNAAAAAgAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIBonvbXy2ARtnNoB",
      "IRBV4L4uEqNTS2tQIH3GfiRnPWUxAAAAoOjMZ4O5qqn4a1imzMS95bkXqdKfku6/E61dJf",
      "twvf0c0HjTtugWo6sGWDvJmKnFkYS4fLibazCYLZHQgYYqUdTRm7p+0cLenc/1lsjNNLVH",
      "LHKXTA9DcN9nTfH/x9VffSwrITZ0CGk2yeilBq0G2ws5zATOS9Psk02NRpfs7e5FTNVI7N",
      "PjWLWZJLZyjDCLOM32DS7dPw1nKIA5QB2QUdU=",
      "-----END OPENSSH PRIVATE KEY-----"
    ].join("\n"),
    publicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBonvbXy2ARtnNoBIRBV4L4uEqNTS2tQIH3GfiRnPWUx"
  },
  ed25519Aes256Gcm: {
    made: "ssh-keygen -t ed25519 -a 2 -Z aes256-gcm@openssh.com",
    privateKey: [
      "-----BEGIN OPENSSH PRIVATE KEY-----",
      "b3BlbnNzaC1rZXktdjEAAAAAFmFlczI1Ni1nY21Ab3BlbnNzaC5jb20AAAAGYmNyeXB0AA",
      "AAGAAAABCDif2KYN5r2z/QTI5GafYFAAAAAgAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAA",
      "IDC1BbPk92vtislaKjnLlBONyCfgV3ZzZfISwI4TYS0uAAAAoNC1i/L2LkVWQ+5gr1bIIR",
      "sh1tgXD6nzPpOXNCdBYEq3kig4pD7qm74lZn09VY+9nkxcf5njvfQQdOn49XdoScZVq+ag",
      "xlUVGlg0zJPE4s2iuz3iFJd/DXpiL3VX6pDU2VBn3UBNPFLhWhetSvJF4g8MBMQPDy7Gs1",
      "5hvwPyfCzrF2KmJ0t+nd/ELcKiypXWmQLPzAGXUAUWCZT751WN5GRPs3PFUUYVJmdjOfgv",
      "hIoy",
      "-----END OPENSSH PRIVATE KEY-----"
    ].join("\n"),
    publicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDC1BbPk92vtislaKjnLlBONyCfgV3ZzZfISwI4TYS0u"
  },
  ed25519ChaCha20Poly1305: {
    made: "ssh-keygen -t ed25519 -a 2 -Z chacha20-poly1305@openssh.com",
    privateKey: [
      "-----BEGIN OPENSSH PRIVATE KEY-----",
      "b3BlbnNzaC1rZXktdjEAAAAAHWNoYWNoYTIwLXBvbHkxMzA1QG9wZW5zc2guY29tAAAABm",
      "JjcnlwdAAAABgAAAAQpQUdLU6I1kB9VAyNC+tCWwAAAAIAAAABAAAAMwAAAAtzc2gtZWQy",
      "NTUxOQAAACBfQ8l9ROj7IMumKovJA0Dx8is3RAgro+l4YGm/VNaPEQAAAJhtcF/v0AF3Y5",
      "uF7MNukkK5r8ToO1pHAHM+kxmRftJMmfUCgPMM2tanDgBc882XkcbVvuCU4clIem4oS8co",
      "elcVpXR0jTLvQMT9tT5ooW8ALIcTktvSOuo6ioRkefiJz5+1vlW3zayhswsGcTMVi3umXD",
      "2eT0NlOOO5owOG8e5nSLvkunix+5X3HYx06D2t64/46gSyFe5C5NyK3oXOEtWih007fNnN",
      "obk=",
      "-----END OPENSSH PRIVATE KEY-----"
    ].join("\n"),
    publicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF9DyX1E6Psgy6Yqi8kDQPHyKzdECCuj6Xhgab9U1o8R"
  },
  ecdsaP256Unencrypted: {
    made: "ssh-keygen -t ecdsa -b 256 -N ''",
    privateKey: [
      "-----BEGIN OPENSSH PRIVATE KEY-----",
      "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS",
      "1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQRgeJOhs8F+EVb5yijyHDOtjw5Rzmtu",
      "gMoeqWIz66VjyUxYK7/Ui6imTdbfFT6xEi2njE7J5oosAx8EFmNxDpuVAAAAsFmxvytZsb",
      "8rAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGB4k6GzwX4RVvnK",
      "KPIcM62PDlHOa26Ayh6pYjPrpWPJTFgrv9SLqKZN1t8VPrESLaeMTsnmiiwDHwQWY3EOm5",
      "UAAAAgByfvxyC2DYsaVz1LEhCgF/ivrmh/npxy0V5opAizhUAAAAATZml4dHVyZS1lY2Rz",
      "YS1wbGFpbgECAwQF",
      "-----END OPENSSH PRIVATE KEY-----"
    ].join("\n"),
    publicKey: "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGB4k6GzwX4RVvnKKPIcM62PDlHOa26Ayh6pYjPrpWPJTFgrv9SLqKZN1t8VPrESLaeMTsnmiiwDHwQWY3EOm5U="
  }
} satisfies Record<string, SshKeyFixture>;
