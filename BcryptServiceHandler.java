import java.lang.reflect.Constructor;
import java.util.ArrayList;
import java.util.List;
import java.util.HashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Set;

import org.mindrot.jbcrypt.BCrypt;

public class BcryptServiceHandler implements BcryptService.Iface {
	public List<String> hashPassword(List<String> password, short logRounds)
			throws IllegalArgument, org.apache.thrift.TException {
		try {
			List<String> ret = new ArrayList<>();

			for (String ps : password) {
				String oneHash = BCrypt.hashpw(ps, BCrypt.gensalt(logRounds));
				ret.add(oneHash);
			}

			return ret;
		} catch (Exception e) {
			throw new IllegalArgument(e.getMessage());
		}
	}

	public List<Boolean> checkPassword(List<String> password, List<String> hash)
			throws IllegalArgument, org.apache.thrift.TException {
		try {
			List<Boolean> ret = new ArrayList<>();
			
			for (int i = 0; i < password.size(); i++) {
				String onePwd = password.get(i);
				String oneHash = hash.get(i);

				ret.add(BCrypt.checkpw(onePwd, oneHash));
			}

			return ret;
		} catch (Exception e) {
			throw new IllegalArgument(e.getMessage());
		}
	}

	@Override
	public void beToFeRegistrar(String beHost, int bePort) {
		throw new UnsupportedOperationException();
	}
}
