import { WitnessContext } from "@midnight-ntwrk/compact-runtime";
import { Ledger } from "./managed/revreg/contract/index.cjs";
export type RevRegPrivateState = {
    readonly secretKey: Uint8Array;
};
export declare const witnesses: {
    localSecretKey: ({ privateState }: WitnessContext<Ledger, RevRegPrivateState>) => [RevRegPrivateState, Uint8Array];
};
