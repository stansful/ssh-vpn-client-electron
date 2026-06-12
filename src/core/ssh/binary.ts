export class SshBinaryWriter {
  private readonly chunks: Buffer[] = [];

  byte(value: number): this {
    this.chunks.push(Buffer.from([value & 0xff]));
    return this;
  }

  boolean(value: boolean): this {
    return this.byte(value ? 1 : 0);
  }

  uint32(value: number): this {
    if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
      throw new Error("uint32 out of range.");
    }
    const buffer = Buffer.allocUnsafe(4);
    buffer.writeUInt32BE(value, 0);
    this.chunks.push(buffer);
    return this;
  }

  string(value: string | Buffer): this {
    const buffer = Buffer.isBuffer(value) ? value : Buffer.from(value, "utf8");
    this.uint32(buffer.length);
    this.chunks.push(buffer);
    return this;
  }

  nameList(values: string[]): this {
    return this.string(values.join(","));
  }

  mpint(value: bigint): this {
    if (value < 0n) {
      throw new Error("negative mpint is not supported yet.");
    }
    if (value === 0n) {
      return this.string(Buffer.alloc(0));
    }

    let hex = value.toString(16);
    if (hex.length % 2 !== 0) {
      hex = `0${hex}`;
    }

    let bytes = Buffer.from(hex, "hex");
    if ((bytes[0] ?? 0) & 0x80) {
      bytes = Buffer.concat([Buffer.from([0]), bytes]);
    }
    return this.string(bytes);
  }

  raw(value: Buffer): this {
    this.chunks.push(value);
    return this;
  }

  toBuffer(): Buffer {
    return Buffer.concat(this.chunks);
  }
}

export class SshBinaryReader {
  private offset = 0;

  constructor(private readonly buffer: Buffer) {}

  byte(): number {
    this.ensure(1);
    const value = this.buffer.readUInt8(this.offset);
    this.offset += 1;
    return value;
  }

  boolean(): boolean {
    return this.byte() !== 0;
  }

  uint32(): number {
    this.ensure(4);
    const value = this.buffer.readUInt32BE(this.offset);
    this.offset += 4;
    return value;
  }

  string(): Buffer {
    const length = this.uint32();
    this.ensure(length);
    const value = this.buffer.subarray(this.offset, this.offset + length);
    this.offset += length;
    return value;
  }

  utf8String(): string {
    return this.string().toString("utf8");
  }

  nameList(): string[] {
    const raw = this.utf8String();
    return raw ? raw.split(",") : [];
  }

  mpint(): bigint {
    const bytes = this.string();
    if (bytes.length === 0) {
      return 0n;
    }
    if ((bytes[0] ?? 0) & 0x80) {
      throw new Error("negative mpint is not supported yet.");
    }
    return BigInt(`0x${bytes.toString("hex")}`);
  }

  remaining(): Buffer {
    return this.buffer.subarray(this.offset);
  }

  eof(): boolean {
    return this.offset === this.buffer.length;
  }

  private ensure(length: number): void {
    if (this.offset + length > this.buffer.length) {
      throw new Error("Unexpected end of SSH binary buffer.");
    }
  }
}
