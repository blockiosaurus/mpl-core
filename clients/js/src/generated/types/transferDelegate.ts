/**
 * This code was AUTOGENERATED using the kinobi library.
 * Please DO NOT EDIT THIS FILE, instead use visitors
 * to add features, then rerun kinobi to update it.
 *
 * @see https://github.com/metaplex-foundation/kinobi
 */

import { Serializer, struct } from '@metaplex-foundation/umi/serializers';

export type TransferDelegate = {};

export type TransferDelegateArgs = TransferDelegate;

export function getTransferDelegateSerializer(): Serializer<
  TransferDelegateArgs,
  TransferDelegate
> {
  return struct<TransferDelegate>([], {
    description: 'TransferDelegate',
  }) as Serializer<TransferDelegateArgs, TransferDelegate>;
}
