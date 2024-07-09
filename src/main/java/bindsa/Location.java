package bindsa;

import java.util.HashSet;
import java.util.Objects;

import ghidra.program.model.address.Address;

public class Location {
	private String key;
	private Long offset;
	private boolean valid;
	
	public Location(String key, Long offset) {
		super();
		this.key = key;
		this.offset = offset;
		this.valid = true;
	}

	public String getKey() {
		return key;
	}

	public void setKey(String key) {
		this.key = key;
	}

	public Long getOffset() {
		return offset;
	}

	public void setOffset(Long offset) {
		this.offset = offset;
	}


	@Override
	public int hashCode() {
		return Objects.hash(key, offset, valid);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		Location other = (Location) obj;
		return Objects.equals(key, other.key) && Objects.equals(offset, other.offset) && valid == other.valid;
	}
	
	
	public boolean isHeap() {
		if (this.getKey().contains("H"))
			return true;
		return false;
	}
	
	public String toString() {
		return key.toString() + "_" + offset.toString();
	}
	
	
}
