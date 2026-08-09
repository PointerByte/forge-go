// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package encrypt

type Repository struct {
	SymmetricRepository
	AsymmetricRepository
	KeyRepository
	SignatureRepository
	HashRepository
}

// NewRepository returns a combined repository with the main cryptographic
// capabilities exposed by this package using the provided implementation.
func NewRepository(input IRepository) *Repository {
	return &Repository{
		SymmetricRepository:  input,
		AsymmetricRepository: input,
		KeyRepository:        input,
		SignatureRepository:  input,
		HashRepository:       input,
	}
}
