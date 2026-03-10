namespace Crypto.Block;

public interface IKeySchedule
{
    byte[][] RoundKeys(byte[] key);
}
