package is.rud.crsspy;

import com.shapesecurity.salvation.data.Notice;
import com.shapesecurity.salvation.data.Origin;
import com.shapesecurity.salvation.ParserWithLocation;
import com.shapesecurity.salvation.data.Policy;
import com.shapesecurity.salvation.data.URI;
import java.util.ArrayList;

public class App {

  public static ArrayList<Notice> get_notices(String policy, String url) {

    ArrayList<Notice> notices = new ArrayList<>();
    Origin origin = URI.parse(url);
    Policy p = ParserWithLocation.parse(policy, url, notices);
    return(notices);
  }

}
