import { describe, expect, it } from "vitest";
import { ContextVerifier } from "../src/library-gatekeeper.js";

describe("ContextVerifier.hasCollectionAccess", () => {
  function createTestVerifier(options: {
    sharingDomain: string;
    accountId: string;
    hasOwned: (collectionId: string) => boolean;
    isPublic: (collectionId: string) => boolean;
    getMetadata: (collectionId: string) => Promise<{ id?: string }>;
  }) {
    const verifier = Object.create(ContextVerifier.prototype) as ContextVerifier;
    (verifier as any).ctx = {
      props: {
        sharingDomain: options.sharingDomain,
        accountId: options.accountId,
      },
      exports: {
        UserLibraryDurableObject: {
          idFromName: (name: string) => name,
          get: (id: string) => ({
            hasOwned: (collectionId: string) => options.hasOwned(collectionId),
          }),
        },
        LibraryRegistryDurableObject: {
          getByName: (domain: string) => ({
            isPublic: (collectionId: string) => options.isPublic(collectionId),
          }),
        },
        ContextCollectionDurableObject: {
          idFromName: (name: string) => name,
          get: (id: string) => ({
            getMetadata: () => options.getMetadata(id),
          }),
        },
      },
    };
    return verifier;
  }

  it("denies access if sharingDomain does not match", async () => {
    const verifier = createTestVerifier({
      sharingDomain: "domain-a",
      accountId: "user-1",
      hasOwned: () => true,
      isPublic: () => true,
      getMetadata: async () => ({ id: "col-1" }),
    });

    expect(await verifier.hasCollectionAccess("domain-b", "col-1")).toBe(false);
  });

  it("allows access if user owns the collection", async () => {
    const verifier = createTestVerifier({
      sharingDomain: "domain-a",
      accountId: "user-1",
      hasOwned: (col) => col === "owned-col",
      isPublic: () => false,
      getMetadata: async () => ({ id: "owned-col" }),
    });

    expect(await verifier.hasCollectionAccess("domain-a", "owned-col")).toBe(true);
  });

  it("allows access if collection is public", async () => {
    const verifier = createTestVerifier({
      sharingDomain: "domain-a",
      accountId: "user-1",
      hasOwned: () => false,
      isPublic: (col) => col === "public-col",
      getMetadata: async () => ({ id: "public-col" }),
    });

    expect(await verifier.hasCollectionAccess("domain-a", "public-col")).toBe(true);
  });

  it("denies access to an existing private collection of another user", async () => {
    const verifier = createTestVerifier({
      sharingDomain: "domain-a",
      accountId: "user-2",
      hasOwned: () => false,
      isPublic: () => false,
      getMetadata: async () => ({ id: "private-col" }),
    });

    expect(await verifier.hasCollectionAccess("domain-a", "private-col")).toBe(false);
  });

  it("allows access if a private collection has been deleted so collaborators are not permanently locked out", async () => {
    const verifier = createTestVerifier({
      sharingDomain: "domain-a",
      accountId: "user-2",
      hasOwned: () => false,
      isPublic: () => false,
      getMetadata: async () => ({ id: undefined }), // deleted collection returns empty metadata
    });

    expect(await verifier.hasCollectionAccess("domain-a", "deleted-col")).toBe(true);
  });
});
