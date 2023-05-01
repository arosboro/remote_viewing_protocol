// The 'remote_viewing_protocol' program.
program remote_viewing_protocol.aleo {

    struct Handle {
        active: bool,
        x_1: u8,
        x_2: u8,
        y_1: u8,
        y_2: u8
    }

    struct Target {
        aes_cmp_target_ciphertext: u64,
        aes_cmp_psk_revealed: u64,
    }

    record RVHandle {
        public owner: address,
        public gates: u64,
        public op: address,
        public handle: Handle,
        public target: Target,
        private aes_cmp_psk: u64,
    }

    mapping handle_sequence: u32 => u32; // value for key 0u32 starts at 0u32 but can be incremented as handles are issued.
    mapping handles: u32 => address; // The original poster of a handle to a remote viewing target.
    mapping handle_map: address => Handle; // The handle to a remote viewing target.

    mapping target_sequence: u32 => u32; // Index key always is 0, but can be incremented as sessions are issued.
    mapping targets: u32 => address; // The original poster of a session to a remote viewing target.
    mapping target_map: address => Target; // The contents of a remote viewing target (Either source description or viewer description).

    transition issue_handle(public x_1: u8, public x_2: u8, public y_1: u8, public y_2: u8, private aes_cmp_target_ciphertext: u64, private aes_cmp_psk: u64) -> RVHandle {
        let handle: Handle = Handle {
            active: true,
            x_1,
            x_2,
            y_1,
            y_2,
        };
        let target: Target = Target {
            aes_cmp_target_ciphertext, // The cipher text of the encrypted remote viewing target.
            aes_cmp_psk_revealed: 0u64, // Unused.
        };
        return RVHandle {
            owner: self.caller, // The caller is the owner of the handle.
            gates: 0u64,
            op: self.caller, // The caller is the owner of the handle.
            handle, // Public descriptor for others to set intention when remote viewing contents of the target_cipher text.
            target, // Public contents of the target cipher text.
            aes_cmp_psk, // Private to the record holder.
        } then finalize (self.caller, handle.active, handle.x_1, handle.x_2, handle.y_1, handle.y_2);
    }

    finalize issue_handle(caller: address, active: bool, x_1: u8, x_2: u8, y_1: u8, y_2: u8) {
        assert(active == true);
        assert(x_1 != 0u8);
        assert(x_2 != 0u8);
        assert(y_1 != 0u8);
        assert(y_2 != 0u8);
        let handle: Handle = Handle {
            active,
            x_1,
            x_2,
            y_1,
            y_2,
        };
        let delta: u32 = Mapping::get_or_init(handle_sequence, 0u32, 0u32);
        Mapping::set(handles, delta, caller);
        Mapping::set(handle_map, caller, handle);
        delta = delta + 1u32;
        Mapping::set(handle_sequence, 0u32, delta);
    }

    transition submit_viewing_session(public op: address, public handle: Handle, public aes_cmp_target_ciphertext: u64, private aes_cmp_psk: u64) -> (RVHandle, RVHandle) {
        let target: Target = Target {
            aes_cmp_target_ciphertext, // the cipher text of the encrypted submission's remote viewing session results.
            aes_cmp_psk_revealed: 0u64, // Unused.
        };
        let response: RVHandle = RVHandle {
            owner: op, // The owner of the handle gets a record of the submission.
            gates: 0u64,
            op, // The owner of the handle gets a record of the submission.
            handle, // Publically used to match caller's submission with the op's handle
            target, // Public contents of the target cipher text.
            aes_cmp_psk: 0u64, // Unused.
        };
        let claim: RVHandle = RVHandle {
            owner: self.caller, // The caller is the owner of a claim to reveal the submission
            gates: 0u64,
            op, // So the caller can find the handle for this submission.
            handle, // Publically used to match caller's submission with the op's handle
            target, // Public contents of the target cipher text.
            aes_cmp_psk, // the pre-shared key used to encrypt the submission's remote viewing session results.
        };
        
        return (response, claim) then finalize (self.caller, op, handle.active, handle.x_1, handle.x_2, handle.y_1, handle.y_2, aes_cmp_target_ciphertext);
    }

    finalize submit_viewing_session (caller: address, op: address, active: bool, x_1: u8, x_2: u8, y_1: u8, y_2: u8, aes_cmp_target_ciphertext: u64) {
        let initial_handle: Handle = Handle {
            active: false,
            x_1: 0u8,
            x_2: 0u8,
            y_1: 0u8,
            y_2: 0u8,
        };
        let handle: Handle = Mapping::get_or_init(handle_map, op, initial_handle);
        assert(handle.active == true);
        assert(handle.x_1 == x_1);
        assert(handle.x_2 == x_2);
        assert(handle.y_1 == y_1);
        assert(handle.y_2 == y_2);
        let delta: u32 = Mapping::get_or_init(target_sequence, 0u32, 0u32);
        let target: Target = Target {
            aes_cmp_target_ciphertext,
            aes_cmp_psk_revealed: 0u64,
        };
        Mapping::set(targets, delta, caller);
        Mapping::set(target_map, caller, target);
        delta = delta + 1u32;
        Mapping::set(target_sequence, 0u32, delta);
    }

    function get_handle_based_on_issuer(caller: address, op: address, rv_handle: Handle) -> Handle {
        assert(rv_handle.active == true);
        if (op == caller) {
            assert(caller == op);
            return Handle {
                active: false,
                x_1: rv_handle.x_1,
                x_2: rv_handle.x_2,
                y_1: rv_handle.y_1,
                y_2: rv_handle.y_2,
            };
        }
        else {
            assert(caller != op);
            return rv_handle;
        }
    }

    transition reveal_target(public rv: RVHandle, public aes_cmp_psk: u64) -> RVHandle {
        assert (aes_cmp_psk == rv.aes_cmp_psk);
        let rv_handle: Handle = rv.handle;
        let rv_target: Target = rv.target;
        assert (rv_target.aes_cmp_psk_revealed == 0u64);
        let handle: Handle = get_handle_based_on_issuer(self.caller, rv.op, rv_handle);
        let target: Target = Target {
            aes_cmp_target_ciphertext: rv_target.aes_cmp_target_ciphertext,
            aes_cmp_psk_revealed: aes_cmp_psk,
        };

        return RVHandle {
            owner: self.caller, // The caller is the owner of the handle.
            gates: 0u64,
            op: rv.op, // The caller is the owner of the handle.
            handle, // Public descriptor for others to set intention when remote viewing contents of the target_cipher text.
            target, // Public contents of the target cipher text.
            aes_cmp_psk, // Private to the record holder.
        } then finalize (self.caller, rv.op, handle.active, target.aes_cmp_target_ciphertext, target.aes_cmp_psk_revealed, handle.x_1, handle.x_2, handle.y_1, handle.y_2);

    }

    finalize reveal_target (caller: address, op: address, active: bool, aes_cmp_target_ciphertext: u64, aes_cmp_psk_revealed: u64, x_1: u8, x_2: u8, y_1: u8, y_2: u8) {
        let initial_handle: Handle = Handle {
            active: true,
            x_1: 0u8,
            x_2: 0u8,
            y_1: 0u8,
            y_2: 0u8,
        };
        let handle: Handle = Mapping::get_or_init(handle_map, op, initial_handle);
        assert(handle.active != active);
        assert(handle.x_1 == x_1);
        assert(handle.x_2 == x_2);
        assert(handle.y_1 == y_1);
        assert(handle.y_2 == y_2);
        let new_handle: Handle = Handle {
            active: false,
            x_1: x_1,
            x_2: x_2,
            y_1: y_1,
            y_2: y_2,
        };
        Mapping::set(handle_map, op, new_handle);
        let target: Target = Target {
            aes_cmp_target_ciphertext,
            aes_cmp_psk_revealed,
        };
        Mapping::set(target_map, caller, target);
    }
        
}
