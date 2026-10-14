"""APDU client for the SHRINCS Nano Gen5 app."""

CLA = 0xE0


class AppClient:
    def __init__(self, backend):
        self.backend = backend

    def version(self):
        return tuple(self.backend.exchange(cla=CLA, ins=0x03).data)

    def name(self):
        return self.backend.exchange(cla=CLA, ins=0x04).data.decode("ascii")

    def sha256(self, message):
        if len(message) > 255:
            raise ValueError("The smoke app accepts at most 255 bytes in one APDU.")
        return self.backend.exchange(cla=CLA, ins=0x10, data=message).data

    def review_hash(self, message):
        if len(message) > 255:
            raise ValueError("The smoke app accepts at most 255 bytes in one APDU.")
        return self.backend.exchange_async(cla=CLA, ins=0x10, p1=1, data=message)

    def profile(self):
        data = self.backend.exchange(cla=CLA, ins=0x05).data
        if len(data) < 36:
            raise ValueError("Truncated profile response")
        return {"protocol": data[0], "max_envelope": int.from_bytes(data[1:3], "big"),
                "profile_id": data[3:35].hex(), "name": data[35:].decode("ascii")}

    def info(self):
        data = self.backend.exchange(cla=CLA, ins=0x06).data
        if len(data) != 69:
            raise ValueError("Invalid info response")
        return {"protocol": data[0], "spec": int.from_bytes(data[1:3], "big"),
                "capabilities": int.from_bytes(data[3:7], "big"),
                "profile_id": data[7:39], "boot_nonce": data[39:55],
                "capacity": int.from_bytes(data[55:59], "big"),
                **{name: int.from_bytes(data[offset:offset+2], "big") for name, offset in
                   [("digest_len", 59), ("max_envelope", 61), ("public_len", 63),
                    ("max_chunk", 65), ("record_version", 67)]}}

    def state(self):
        data = self.backend.exchange(cla=CLA, ins=0x32).data
        if len(data) != 110 or data[0] > 3:
            raise ValueError("Invalid state response")
        return {"state": data[0], "commitment": data[1:33], "generation": data[33:65],
                **{name: int.from_bytes(data[offset:offset+4], "big") for name, offset in
                   [("capacity", 65), ("next_leaf", 69), ("stateless_used", 73), ("stateless_limit", 77)]},
                "sequence": int.from_bytes(data[81:89], "big"), "operation": data[89],
                "signer_token": data[90:]}

    def create_key(self, profile_id):
        if len(profile_id) != 32:
            raise ValueError("Profile ID must be 32 bytes")
        return self.backend.exchange_async(cla=CLA, ins=0x30,
                                           data=profile_id + (4).to_bytes(4, "big"))

    def public_chunk(self, commitment, offset, length):
        if len(commitment) != 32 or not 1 <= length <= 200 or not 0 <= offset < 480 or offset + length > 480:
            raise ValueError("Invalid public key range")
        prefix = commitment + (480).to_bytes(2, "big") + offset.to_bytes(2, "big") + bytes([length])
        data = self.backend.exchange(cla=CLA, ins=0x31,
                                     data=commitment + offset.to_bytes(2, "big") + bytes([length])).data
        if len(data) != 37 + length or data[:37] != prefix:
            raise ValueError("Invalid public key response")
        return data[37:]

    def public_key(self, commitment):
        return b"".join(self.public_chunk(commitment, offset, min(200, 480-offset))
                        for offset in range(0, 480, 200))

    def begin(self, case, length=None):
        envelope = bytes.fromhex(case["envelope"])
        length = len(envelope) if length is None else length
        data = bytes.fromhex(case["commitment"]) + bytes.fromhex(case["hash"]) + length.to_bytes(4, "big")
        reply = self.backend.exchange(cla=CLA, ins=0x20, data=data).data
        if len(reply) != 4:
            raise ValueError("Invalid session response")
        return int.from_bytes(reply, "big")

    def write(self, session, offset, chunk):
        if len(chunk) > 251:
            raise ValueError("At most 251 envelope bytes fit in one APDU")
        p1, p2 = offset.to_bytes(2, "big")
        reply = self.backend.exchange(cla=CLA, ins=0x21, p1=p1, p2=p2,
                                      data=session.to_bytes(4, "big") + chunk).data
        if len(reply) != 2:
            raise ValueError("Invalid upload response")
        return int.from_bytes(reply, "big")

    def finish(self, session):
        reply = self.backend.exchange(cla=CLA, ins=0x22, data=session.to_bytes(4, "big")).data
        if len(reply) != 1 or reply[0] not in (0, 1, 2):
            raise ValueError("Invalid verification response")
        return reply[0]

    def cancel(self):
        return self.backend.exchange(cla=CLA, ins=0x23).data

    def verify(self, case, chunk_size=251):
        if not 1 <= chunk_size <= 251:
            raise ValueError("chunk_size must be 1..251")
        envelope = bytes.fromhex(case["envelope"])
        session = self.begin(case)
        try:
            for offset in range(0, len(envelope), chunk_size):
                chunk = envelope[offset:offset + chunk_size]
                if self.write(session, offset, chunk) != offset + len(chunk):
                    raise ValueError("Unexpected upload offset")
            return self.finish(session)
        finally:
            self.cancel()
