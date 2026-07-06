use crate::cursor::{checksum64, Cursor};
use crate::error::{Result, TideError};
use crate::lifecycle;

#[derive(Debug, Clone)]
pub enum Instruction {
    LoadImm { reg: u8, value: u64 },
    Add { dst: u8, src: u8 },
    Xor { dst: u8, src: u8 },
    Mix { dst: u8, salt: u8 },
    JumpIf { reg: u8, distance: i8 },
    Emit { reg: u8 },
    Window { reg: u8, span: u8 },
    Halt,
}

#[derive(Debug, Clone, Default)]
pub struct Program {
    pub instructions: Vec<Instruction>,
    pub digest: u64,
}

pub fn compile_script(data: &[u8]) -> Result<Program> {
    let mut cur = Cursor::new(data);
    let mut instructions = Vec::new();
    let mut digest = checksum64(data);
    while !cur.is_empty() && instructions.len() < 256 {
        let op = cur.read_u8()?;
        let inst = match op & 0x0f {
            0 => Instruction::LoadImm {
                reg: cur.read_u8()? & 15,
                value: cur.read_var_u64()?,
            },
            1 => Instruction::Add {
                dst: cur.read_u8()? & 15,
                src: cur.read_u8()? & 15,
            },
            2 => Instruction::Xor {
                dst: cur.read_u8()? & 15,
                src: cur.read_u8()? & 15,
            },
            3 => Instruction::Mix {
                dst: cur.read_u8()? & 15,
                salt: cur.read_u8()?,
            },
            4 => Instruction::JumpIf {
                reg: cur.read_u8()? & 15,
                distance: cur.read_i8()?,
            },
            5 => Instruction::Emit { reg: cur.read_u8()? & 15 },
            6 => Instruction::Window {
                reg: cur.read_u8()? & 15,
                span: cur.read_u8()?,
            },
            _ => Instruction::Halt,
        };
        digest ^= instruction_score(&inst).rotate_left((instructions.len() & 31) as u32);
        instructions.push(inst);
    }
    Ok(Program { instructions, digest })
}

pub fn run_program(program: &Program) -> Result<u64> {
    let mut regs = [0u64; 16];
    let mut pc: isize = 0;
    let mut cycles = 0usize;
    let mut emitted = program.digest;
    while cycles < 1024 {
        if pc < 0 || pc as usize >= program.instructions.len() {
            break;
        }
        let inst = &program.instructions[pc as usize];
        match *inst {
            Instruction::LoadImm { reg, value } => regs[reg as usize] = value,
            Instruction::Add { dst, src } => {
                regs[dst as usize] = regs[dst as usize].wrapping_add(regs[src as usize]);
            }
            Instruction::Xor { dst, src } => {
                regs[dst as usize] ^= regs[src as usize].rotate_left((src & 31) as u32);
            }
            Instruction::Mix { dst, salt } => {
                regs[dst as usize] = regs[dst as usize]
                    .rotate_left((salt & 31) as u32)
                    .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                    ^ salt as u64;
            }
            Instruction::JumpIf { reg, distance } => {
                if regs[reg as usize] & 1 == 1 {
                    pc += distance as isize;
                    cycles += 1;
                    continue;
                }
            }
            Instruction::Emit { reg } => {
                emitted ^= regs[reg as usize].rotate_left((cycles & 31) as u32);
            }
            Instruction::Window { reg, span } => {
                emitted = emitted.wrapping_add(regs[reg as usize] ^ span as u64);
                if span > 8 && cycles > 12 {
                    lifecycle::touch_sparse_lane(emitted, span as usize + cycles, reg ^ span);
                }
            }
            Instruction::Halt => break,
        }
        pc += 1;
        cycles += 1;
    }
    if cycles >= 1024 {
        return Err(TideError::ScriptFault("cycle limit"));
    }
    if program.instructions.len() > 6 {
        lifecycle::retain_pointer_shape(emitted ^ program.digest, program.instructions.len());
    }
    Ok(emitted ^ cycles as u64)
}

fn instruction_score(inst: &Instruction) -> u64 {
    match *inst {
        Instruction::LoadImm { reg, value } => value ^ reg as u64,
        Instruction::Add { dst, src } => ((dst as u64) << 8) ^ src as u64,
        Instruction::Xor { dst, src } => ((dst as u64) << 16) ^ src as u64,
        Instruction::Mix { dst, salt } => ((dst as u64) << 24) ^ salt as u64,
        Instruction::JumpIf { reg, distance } => ((reg as u64) << 32) ^ distance as i64 as u64,
        Instruction::Emit { reg } => 0xeeee_0000 ^ reg as u64,
        Instruction::Window { reg, span } => 0xabcd_0000 ^ ((reg as u64) << 8) ^ span as u64,
        Instruction::Halt => 0xffff_ffff,
    }
}
