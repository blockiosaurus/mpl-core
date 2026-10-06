import test from 'ava';

import { generateSigner } from '@metaplex-foundation/umi';
import { generateSignerWithSol } from '@metaplex-foundation/umi-bundle-tests';
import {
  DEFAULT_ASSET,
  DEFAULT_COLLECTION,
  assertAsset,
  assertCollection,
  createUmi,
} from '../../_setupRaw';
import { createAsset, createCollection } from '../../_setupSdk';
import { addPlugin, updateCollectionPlugin } from '../../../src';

test('it can create collection with verified creators plugin', async (t) => {
  const umi = await createUmi();

  const collection = await createCollection(umi, {
    plugins: [
      {
        type: 'VerifiedCreators',
        signatures: [
          {
            address: umi.identity.publicKey,
            verified: true,
          },
        ],
      },
    ],
  });

  await assertCollection(t, umi, {
    ...DEFAULT_COLLECTION,
    collection: collection.publicKey,
    updateAuthority: umi.identity.publicKey,
    verifiedCreators: {
      authority: {
        type: 'UpdateAuthority',
      },
      signatures: [
        {
          address: umi.identity.publicKey,
          verified: true,
        },
      ],
    },
  });
});

test('it cannot create collection with verified creators plugin and unauthorized signature', async (t) => {
  const umi = await createUmi();
  const creator = generateSigner(umi);

  const res = createCollection(umi, {
    plugins: [
      {
        type: 'VerifiedCreators',
        signatures: [
          {
            address: creator.publicKey,
            verified: true,
          },
        ],
      },
    ],
  });

  await t.throwsAsync(res, { name: 'MissingSigner' });
});

test('it can create asset in collection with verified creators plugin as update delegate', async (t) => {
  const umi = await createUmi();
  const updateDelegate = await generateSignerWithSol(umi);

  // The collection carries a verified creator (the update authority) that is
  // not the signer creating the asset.
  const collection = await createCollection(umi, {
    plugins: [
      {
        type: 'VerifiedCreators',
        signatures: [
          {
            address: umi.identity.publicKey,
            verified: true,
          },
        ],
      },
      {
        type: 'UpdateDelegate',
        additionalDelegates: [updateDelegate.publicKey],
      },
    ],
  });

  umi.identity = updateDelegate;
  umi.payer = updateDelegate;
  const owner = generateSigner(umi);

  const asset = await createAsset(umi, {
    collection: collection.publicKey,
    owner,
    authority: updateDelegate,
  });

  await assertAsset(t, umi, {
    ...DEFAULT_ASSET,
    asset: asset.publicKey,
    owner: owner.publicKey,
    updateAuthority: { type: 'Collection', address: collection.publicKey },
  });
});

test('it can print edition into master edition collection with verified creators plugin as update delegate', async (t) => {
  const umi = await createUmi();
  const updateDelegate = await generateSignerWithSol(umi);

  const collection = await createCollection(umi, {
    plugins: [
      {
        type: 'MasterEdition',
        maxSupply: 100,
        name: 'name',
        uri: 'uri',
      },
      {
        type: 'VerifiedCreators',
        signatures: [
          {
            address: umi.identity.publicKey,
            verified: true,
          },
        ],
      },
      {
        type: 'UpdateDelegate',
        additionalDelegates: [updateDelegate.publicKey],
      },
    ],
  });

  umi.identity = updateDelegate;
  umi.payer = updateDelegate;
  const owner = generateSigner(umi);

  const asset = await createAsset(umi, {
    collection: collection.publicKey,
    owner,
    authority: updateDelegate,
    plugins: [
      {
        type: 'Edition',
        number: 1,
      },
    ],
  });

  await assertAsset(t, umi, {
    ...DEFAULT_ASSET,
    asset: asset.publicKey,
    owner: owner.publicKey,
    updateAuthority: { type: 'Collection', address: collection.publicKey },
    edition: {
      authority: {
        type: 'UpdateAuthority',
      },
      number: 1,
    },
  });
});

test('it can create asset in collection with verified creator other than the authority', async (t) => {
  const umi = await createUmi();
  const creator = await generateSignerWithSol(umi);

  const collection = await createCollection(umi, {
    plugins: [
      {
        type: 'VerifiedCreators',
        signatures: [
          {
            address: umi.identity.publicKey,
            verified: true,
          },
          {
            address: creator.publicKey,
            verified: false,
          },
        ],
      },
    ],
  });

  // The creator verifies themselves on the collection.
  await updateCollectionPlugin(umi, {
    collection: collection.publicKey,
    plugin: {
      type: 'VerifiedCreators',
      signatures: [
        {
          address: umi.identity.publicKey,
          verified: true,
        },
        {
          address: creator.publicKey,
          verified: true,
        },
      ],
    },
    authority: creator,
  }).sendAndConfirm(umi);

  await assertCollection(t, umi, {
    ...DEFAULT_COLLECTION,
    collection: collection.publicKey,
    updateAuthority: umi.identity.publicKey,
    verifiedCreators: {
      authority: {
        type: 'UpdateAuthority',
      },
      signatures: [
        {
          address: umi.identity.publicKey,
          verified: true,
        },
        {
          address: creator.publicKey,
          verified: true,
        },
      ],
    },
  });

  // The update authority can still create assets even though another verified
  // creator exists on the collection.
  const owner = generateSigner(umi);
  const asset = await createAsset(umi, {
    collection: collection.publicKey,
    owner,
  });

  await assertAsset(t, umi, {
    ...DEFAULT_ASSET,
    asset: asset.publicKey,
    owner: owner.publicKey,
    updateAuthority: { type: 'Collection', address: collection.publicKey },
  });
});

test('it cannot create asset with unauthorized verified signature in collection with verified creators plugin', async (t) => {
  const umi = await createUmi();
  const updateDelegate = await generateSignerWithSol(umi);

  const collection = await createCollection(umi, {
    plugins: [
      {
        type: 'VerifiedCreators',
        signatures: [
          {
            address: umi.identity.publicKey,
            verified: true,
          },
        ],
      },
      {
        type: 'UpdateDelegate',
        additionalDelegates: [updateDelegate.publicKey],
      },
    ],
  });

  umi.identity = updateDelegate;
  umi.payer = updateDelegate;
  const owner = generateSigner(umi);

  // The asset's own verified creators plugin is still validated: the delegate
  // cannot sign for the collection's update authority.
  const res = createAsset(umi, {
    collection: collection.publicKey,
    owner,
    authority: updateDelegate,
    plugins: [
      {
        type: 'VerifiedCreators',
        signatures: [
          {
            address: collection.updateAuthority,
            verified: true,
          },
        ],
      },
    ],
  });

  await t.throwsAsync(res, { name: 'MissingSigner' });
});

test('it can create asset with own verified signature in collection with verified creators plugin', async (t) => {
  const umi = await createUmi();
  const updateDelegate = await generateSignerWithSol(umi);

  const collection = await createCollection(umi, {
    plugins: [
      {
        type: 'VerifiedCreators',
        signatures: [
          {
            address: umi.identity.publicKey,
            verified: true,
          },
        ],
      },
      {
        type: 'UpdateDelegate',
        additionalDelegates: [updateDelegate.publicKey],
      },
    ],
  });

  umi.identity = updateDelegate;
  umi.payer = updateDelegate;
  const owner = generateSigner(umi);

  const asset = await createAsset(umi, {
    collection: collection.publicKey,
    owner,
    authority: updateDelegate,
    plugins: [
      {
        type: 'VerifiedCreators',
        signatures: [
          {
            address: updateDelegate.publicKey,
            verified: true,
          },
        ],
      },
    ],
  });

  await assertAsset(t, umi, {
    ...DEFAULT_ASSET,
    asset: asset.publicKey,
    owner: owner.publicKey,
    updateAuthority: { type: 'Collection', address: collection.publicKey },
    verifiedCreators: {
      authority: {
        type: 'UpdateAuthority',
      },
      signatures: [
        {
          address: updateDelegate.publicKey,
          verified: true,
        },
      ],
    },
  });
});

test('it can add verified creators plugin to asset in collection with verified creators plugin as update delegate', async (t) => {
  const umi = await createUmi();
  const updateDelegate = await generateSignerWithSol(umi);

  const collection = await createCollection(umi, {
    plugins: [
      {
        type: 'VerifiedCreators',
        signatures: [
          {
            address: umi.identity.publicKey,
            verified: true,
          },
        ],
      },
      {
        type: 'UpdateDelegate',
        additionalDelegates: [updateDelegate.publicKey],
      },
    ],
  });

  umi.identity = updateDelegate;
  umi.payer = updateDelegate;
  const owner = generateSigner(umi);

  const asset = await createAsset(umi, {
    collection: collection.publicKey,
    owner,
    authority: updateDelegate,
  });

  await addPlugin(umi, {
    asset: asset.publicKey,
    collection: collection.publicKey,
    plugin: {
      type: 'VerifiedCreators',
      signatures: [
        {
          address: updateDelegate.publicKey,
          verified: true,
        },
      ],
    },
    authority: updateDelegate,
  }).sendAndConfirm(umi);

  await assertAsset(t, umi, {
    ...DEFAULT_ASSET,
    asset: asset.publicKey,
    owner: owner.publicKey,
    updateAuthority: { type: 'Collection', address: collection.publicKey },
    verifiedCreators: {
      authority: {
        type: 'UpdateAuthority',
      },
      signatures: [
        {
          address: updateDelegate.publicKey,
          verified: true,
        },
      ],
    },
  });
});
