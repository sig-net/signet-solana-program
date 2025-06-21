#![allow(unexpected_cfgs)]
use anchor_lang::prelude::*;

declare_id!("4uvZW8K4g4jBg7dzPNbb9XDxJLFBK7V6iC76uofmYvEU");

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug, PartialEq)]
#[repr(u8)]
pub enum SerializationFormat {
    Borsh = 0,
    AbiJson = 1,
}

#[program]
pub mod chain_signatures_project {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>, signature_deposit: u64) -> Result<()> {
        let program_state = &mut ctx.accounts.program_state;
        program_state.admin = ctx.accounts.admin.key();
        program_state.signature_deposit = signature_deposit;

        Ok(())
    }

    pub fn update_deposit(ctx: Context<AdminOnly>, new_deposit: u64) -> Result<()> {
        let program_state = &mut ctx.accounts.program_state;
        program_state.signature_deposit = new_deposit;

        emit!(DepositUpdatedEvent {
            old_deposit: program_state.signature_deposit,
            new_deposit,
        });

        Ok(())
    }

    pub fn withdraw_funds(ctx: Context<WithdrawFunds>, amount: u64) -> Result<()> {
        let program_state = &ctx.accounts.program_state;
        let recipient = &ctx.accounts.recipient;

        let program_state_info = program_state.to_account_info();
        require!(
            program_state_info.lamports() >= amount,
            ChainSignaturesError::InsufficientFunds
        );

        require!(
            recipient.key() != Pubkey::default(),
            ChainSignaturesError::InvalidRecipient
        );

        // Transfer funds from program_state to recipient
        **program_state_info.try_borrow_mut_lamports()? -= amount;
        **recipient.try_borrow_mut_lamports()? += amount;

        emit!(FundsWithdrawnEvent {
            amount,
            recipient: recipient.key(),
        });

        Ok(())
    }

    pub fn sign(
        ctx: Context<Sign>,
        payload: [u8; 32],
        key_version: u32,
        path: String,
        algo: String,
        dest: String,
        params: String,
    ) -> Result<()> {
        let program_state = &ctx.accounts.program_state;
        let requester = &ctx.accounts.requester;
        let system_program = &ctx.accounts.system_program;

        let payer = match &ctx.accounts.fee_payer {
            Some(fee_payer) => fee_payer.to_account_info(),
            None => requester.to_account_info(),
        };

        require!(
            payer.lamports() >= program_state.signature_deposit,
            ChainSignaturesError::InsufficientDeposit
        );

        let transfer_instruction = anchor_lang::system_program::Transfer {
            from: payer,
            to: program_state.to_account_info(),
        };

        anchor_lang::system_program::transfer(
            CpiContext::new(system_program.to_account_info(), transfer_instruction),
            program_state.signature_deposit,
        )?;

        emit_cpi!(SignatureRequestedEvent {
            sender: *requester.key,
            payload,
            key_version,
            deposit: program_state.signature_deposit,
            chain_id: 0,
            path,
            algo,
            dest,
            params,
            fee_payer: match &ctx.accounts.fee_payer {
                Some(payer) => Some(*payer.key),
                None => None,
            },
        });

        Ok(())
    }

    pub fn sign_respond(
        ctx: Context<SignRespond>,
        transaction: Vec<u8>,
        slip44_chain_id: u32,
        key_version: u32,
        path: String,
        algo: String,
        dest: String,
        params: String,
        deserialization_format: SerializationFormat,
        deserialization_schema: Vec<u8>,
        serialization_format: SerializationFormat,
        serialization_schema: Vec<u8>,
    ) -> Result<()> {
        let program_state = &ctx.accounts.program_state;
        let requester = &ctx.accounts.requester;
        let system_program = &ctx.accounts.system_program;

        let instructions = ctx
            .accounts
            .instructions
            .as_ref()
            .ok_or(ChainSignaturesError::MissingInstructionSysvar)?;
        let current_index =
            anchor_lang::solana_program::sysvar::instructions::load_current_index_checked(
                instructions,
            )?;

        let predecessor = if current_index > 0 {
            let caller_instruction =
                anchor_lang::solana_program::sysvar::instructions::load_instruction_at_checked(
                    (current_index - 1) as usize,
                    instructions,
                )?;
            caller_instruction.program_id
        } else {
            *requester.key
        };

        let payer = match &ctx.accounts.fee_payer {
            Some(fee_payer) => fee_payer.to_account_info(),
            None => requester.to_account_info(),
        };

        require!(
            payer.lamports() >= program_state.signature_deposit,
            ChainSignaturesError::InsufficientDeposit
        );

        require!(
            !transaction.is_empty(),
            ChainSignaturesError::InvalidTransaction
        );

        let transfer_instruction = anchor_lang::system_program::Transfer {
            from: payer,
            to: program_state.to_account_info(),
        };

        anchor_lang::system_program::transfer(
            CpiContext::new(system_program.to_account_info(), transfer_instruction),
            program_state.signature_deposit,
        )?;

        emit!(SignRespondRequestedEvent {
            predecessor,
            sender: *requester.key,
            transaction_data: transaction,
            slip44_chain_id,
            key_version,
            deposit: program_state.signature_deposit,
            path,
            algo,
            dest,
            params,
            deserialization_format: deserialization_format as u8,
            deserialization_schema,
            serialization_format: serialization_format as u8,
            serialization_schema,
            fee_payer: match &ctx.accounts.fee_payer {
                Some(payer) => Some(*payer.key),
                None => None,
            },
        });

        Ok(())
    }

    pub fn respond(
        ctx: Context<Respond>,
        request_ids: Vec<[u8; 32]>,
        signatures: Vec<Signature>,
    ) -> Result<()> {
        require!(
            request_ids.len() == signatures.len(),
            ChainSignaturesError::InvalidInputLength
        );

        for i in 0..request_ids.len() {
            emit!(SignatureRespondedEvent {
                request_id: request_ids[i],
                responder: *ctx.accounts.responder.key,
                signature: signatures[i].clone(),
            });
        }

        Ok(())
    }
}

#[account]
pub struct ProgramState {
    pub admin: Pubkey,
    pub signature_deposit: u64,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct AffinePoint {
    pub x: [u8; 32],
    pub y: [u8; 32],
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct Signature {
    pub big_r: AffinePoint,
    pub s: [u8; 32],
    pub recovery_id: u8,
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = admin,
        space = 8 + 32 + 8,
        seeds = [b"program-state"],
        bump
    )]
    pub program_state: Account<'info, ProgramState>,
    #[account(mut)]
    pub admin: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct AdminOnly<'info> {
    #[account(
        mut,
        seeds = [b"program-state"],
        bump,
        has_one = admin @ ChainSignaturesError::Unauthorized
    )]
    pub program_state: Account<'info, ProgramState>,
    #[account(mut)]
    pub admin: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct WithdrawFunds<'info> {
    #[account(
        mut,
        seeds = [b"program-state"],
        bump,
        has_one = admin @ ChainSignaturesError::Unauthorized
    )]
    pub program_state: Account<'info, ProgramState>,

    #[account(mut)]
    pub admin: Signer<'info>,

    /// CHECK: The safety check is performed in the withdraw_funds
    /// function by checking it is not the zero address.
    #[account(mut)]
    pub recipient: AccountInfo<'info>,

    pub system_program: Program<'info, System>,
}

#[event_cpi]
#[derive(Accounts)]
pub struct Sign<'info> {
    #[account(mut, seeds = [b"program-state"], bump)]
    pub program_state: Account<'info, ProgramState>,
    #[account(mut)]
    pub requester: Signer<'info>,
    #[account(mut)]
    pub fee_payer: Option<Signer<'info>>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SignRespond<'info> {
    #[account(mut, seeds = [b"program-state"], bump)]
    pub program_state: Account<'info, ProgramState>,
    #[account(mut)]
    pub requester: Signer<'info>,
    #[account(mut)]
    pub fee_payer: Option<Signer<'info>>,
    pub system_program: Program<'info, System>,
    pub instructions: Option<AccountInfo<'info>>,
}

#[derive(Accounts)]
pub struct Respond<'info> {
    pub responder: Signer<'info>,
}

#[event]
pub struct SignatureRequestedEvent {
    pub sender: Pubkey,
    pub payload: [u8; 32],
    pub key_version: u32,
    pub deposit: u64,
    pub chain_id: u64,
    pub path: String,
    pub algo: String,
    pub dest: String,
    pub params: String,
    pub fee_payer: Option<Pubkey>,
}

#[event]
pub struct SignRespondRequestedEvent {
    pub predecessor: Pubkey,
    pub sender: Pubkey,
    pub transaction_data: Vec<u8>,
    pub slip44_chain_id: u32,
    pub key_version: u32,
    pub deposit: u64,
    pub path: String,
    pub algo: String,
    pub dest: String,
    pub params: String,
    pub deserialization_format: u8,
    pub deserialization_schema: Vec<u8>,
    pub serialization_format: u8,
    pub serialization_schema: Vec<u8>,
    pub fee_payer: Option<Pubkey>,
}

#[event]
pub struct SignatureErrorEvent {
    pub request_id: [u8; 32],
    pub responder: Pubkey,
    pub error: String,
}

#[event]
pub struct SignatureRespondedEvent {
    pub request_id: [u8; 32],
    pub responder: Pubkey,
    pub signature: Signature,
}

#[event]
pub struct DepositUpdatedEvent {
    pub old_deposit: u64,
    pub new_deposit: u64,
}

#[event]
pub struct FundsWithdrawnEvent {
    pub amount: u64,
    pub recipient: Pubkey,
}

#[error_code]
pub enum ChainSignaturesError {
    #[msg("Insufficient deposit amount")]
    InsufficientDeposit,
    #[msg("Arrays must have the same length")]
    InvalidInputLength,
    #[msg("Unauthorized access")]
    Unauthorized,
    #[msg("Insufficient funds for withdrawal")]
    InsufficientFunds,
    #[msg("Invalid recipient address")]
    InvalidRecipient,
    #[msg("Invalid transaction data")]
    InvalidTransaction,
    #[msg("Missing instruction sysvar")]
    MissingInstructionSysvar,
}
